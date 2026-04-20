"""
Dashboard Server.

Provides:
  - Static file serving for the web UI (HTML/CSS/JS)
  - REST API endpoints for events, decisions, audit, stats
  - WebSocket endpoint for real-time event streaming
  - Integration with GozcuPipeline for live data
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Set

from aiohttp import web, WSMsgType

from gozcu.config import Config
from gozcu.main import GozcuPipeline
from gozcu.models.enums import SourceType

logger = logging.getLogger(__name__)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


class DashboardServer:
    """
    aiohttp-based dashboard server with WebSocket support.

    Serves the web UI and provides real-time updates via WebSocket.
    # on yuz (frontend) ile arka planin (backend) haberlesmesini saglayan kopru burasi.
    """

    def __init__(self, pipeline: GozcuPipeline, config: Config) -> None:
        self._pipeline = pipeline
        self._config = config
        self._app = web.Application()
        self._ws_clients: Set[web.WebSocketResponse] = set()
        self._setup_routes()

        # Wire broadcast into the pipeline
        pipeline.set_broadcast(self._broadcast)

    def _setup_routes(self) -> None:
        """Register all HTTP and WebSocket routes."""
        self._app.router.add_get("/ws", self._ws_handler)

        # REST API
        self._app.router.add_get("/api/events", self._api_events)
        self._app.router.add_get("/api/decisions", self._api_decisions)
        self._app.router.add_post("/api/decisions/{decision_id}/approve", self._api_approve)
        self._app.router.add_post("/api/decisions/{decision_id}/reject", self._api_reject)
        self._app.router.add_get("/api/audit", self._api_audit)
        self._app.router.add_get("/api/stats", self._api_stats)
        self._app.router.add_post("/api/submit", self._api_submit)

        # Static files (serve index.html for root)
        self._app.router.add_get("/", self._serve_index)
        if STATIC_DIR.exists():
            self._app.router.add_static("/static", STATIC_DIR, show_index=False)

    # --- WebSocket ---

    async def _ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connections for real-time updates."""
        # websocket baglantisi kurup kullaniciya canli veri (stream) akisi sagliyorum.
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self._ws_clients.add(ws)
        logger.info(f"WebSocket client connected ({len(self._ws_clients)} total)")

        # Send initial state
        try:
            await ws.send_json({
                "type": "init",
                "events": self._pipeline.get_events()[-50:],  # Last 50
                "active_decisions": self._pipeline.get_active_decisions(),
                "stats": self._pipeline.get_stats(),
            })
        except Exception as e:
            logger.debug(f"Failed to send init: {e}")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await self._handle_ws_message(ws, msg.data)
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            self._ws_clients.discard(ws)
            logger.info(f"WebSocket client disconnected ({len(self._ws_clients)} total)")

        return ws

    async def _handle_ws_message(self, ws: web.WebSocketResponse, data: str) -> None:
        """Handle incoming WebSocket messages from the client."""
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return

        msg_type = msg.get("type", "")

        if msg_type == "approve":
            decision_id = msg.get("decision_id", "")
            analyst = msg.get("analyst", "dashboard_user")
            success = self._pipeline.approve_decision(decision_id, analyst)
            await ws.send_json({"type": "action_result", "action": "approve", "success": success})

        elif msg_type == "reject":
            decision_id = msg.get("decision_id", "")
            analyst = msg.get("analyst", "dashboard_user")
            success = self._pipeline.reject_decision(decision_id, analyst)
            await ws.send_json({"type": "action_result", "action": "reject", "success": success})

    async def _broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected WebSocket clients."""
        if not self._ws_clients:
            return

        dead: list[web.WebSocketResponse] = []
        payload = json.dumps(message, default=str)

        for ws in self._ws_clients:
            try:
                await ws.send_str(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self._ws_clients.discard(ws)

    # --- REST API ---

    async def _api_events(self, request: web.Request) -> web.Response:
        """GET /api/events — Return all processed events."""
        events = self._pipeline.get_events()
        return web.json_response(events, dumps=lambda x: json.dumps(x, default=str))

    async def _api_decisions(self, request: web.Request) -> web.Response:
        """GET /api/decisions — Return active pending decisions."""
        decisions = self._pipeline.get_active_decisions()
        return web.json_response(decisions)

    async def _api_approve(self, request: web.Request) -> web.Response:
        """POST /api/decisions/{id}/approve — Approve a decision."""
        decision_id = request.match_info["decision_id"]
        body = await request.json() if request.can_read_body else {}
        analyst = body.get("analyst", "api_user")
        success = self._pipeline.approve_decision(decision_id, analyst)
        return web.json_response({"success": success})

    async def _api_reject(self, request: web.Request) -> web.Response:
        """POST /api/decisions/{id}/reject — Reject a decision."""
        decision_id = request.match_info["decision_id"]
        body = await request.json() if request.can_read_body else {}
        analyst = body.get("analyst", "api_user")
        success = self._pipeline.reject_decision(decision_id, analyst)
        return web.json_response({"success": success})

    async def _api_audit(self, request: web.Request) -> web.Response:
        """GET /api/audit — Return audit trail records."""
        records = await self._pipeline.get_audit_history()
        return web.json_response(records, dumps=lambda x: json.dumps(x, default=str))

    async def _api_stats(self, request: web.Request) -> web.Response:
        """GET /api/stats — Return pipeline statistics."""
        stats = self._pipeline.get_stats()
        return web.json_response(stats, dumps=lambda x: json.dumps(x, default=str))

    async def _api_submit(self, request: web.Request) -> web.Response:
        """POST /api/submit — Submit a raw log for processing."""
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        raw_data = body.get("raw_data", "")
        source_type_str = body.get("source_type", "WEB_LOG")
        source_ip = body.get("source_ip", "0.0.0.0")

        try:
            source_type = SourceType(source_type_str)
        except ValueError:
            return web.json_response({"error": f"Invalid source_type: {source_type_str}"}, status=400)

        result = await self._pipeline.process_event(raw_data, source_type, source_ip)
        if result is None:
            return web.json_response({"error": "Empty log data"}, status=400)

        return web.json_response(result, dumps=lambda x: json.dumps(x, default=str))

    # --- Static Files ---

    async def _serve_index(self, request: web.Request) -> web.Response:
        """Serve the main dashboard HTML."""
        index_path = STATIC_DIR / "index.html"
        if not index_path.exists():
            return web.Response(
                text="Dashboard UI not found. Build step 14-16 first.",
                content_type="text/plain",
                status=404,
            )
        return web.FileResponse(index_path)

    # --- Server Lifecycle ---

    async def start(self) -> web.AppRunner:
        """Start the dashboard server."""
        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(
            runner,
            self._config.DASHBOARD_HOST,
            self._config.DASHBOARD_PORT,
        )
        await site.start()
        logger.info(
            f"Dashboard running at http://{self._config.DASHBOARD_HOST}:{self._config.DASHBOARD_PORT}"
        )
        return runner
