"""
Action Executor.

Executes mitigation actions (IP blocking, null-routing, service restart)
in either simulation mode or real mode. Always checks the whitelist
BEFORE executing any action.
"""

from __future__ import annotations

import logging
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from gozcu.decision.whitelist import WhitelistManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ActionResult:
    """Result of an executed action."""
    success: bool
    action: str
    target: str
    message: str
    simulated: bool
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ActionExecutor:
    """
    Executes mitigation actions with whitelist protection.

    In simulation mode (default), no real system commands are executed.
    All actions are logged regardless of mode.
    """

    def __init__(
        self,
        whitelist: WhitelistManager,
        simulation_mode: bool = True,
    ) -> None:
        self._whitelist = whitelist
        self._simulation_mode = simulation_mode
        self._history: list[ActionResult] = []

    async def execute(self, action: str, target: str) -> ActionResult:
        """
        Execute a mitigation action against a target.

        FIRST LINE: Whitelist check — whitelisted targets are NEVER actioned.

        Args:
            action: Action type (BLOCK_IP, NULL_ROUTE, RESTART_SERVICE, QUARANTINE)
            target: Target IP, service name, or resource identifier
        """
        # === WHITELIST CHECK — ALWAYS FIRST ===
        if self._is_protected(action, target):
            result = ActionResult(
                success=False,
                action=action,
                target=target,
                message=f"BLOCKED: Target '{target}' is whitelisted — action refused",
                simulated=self._simulation_mode,
            )
            logger.warning(
                f"Action REFUSED — whitelisted target: {target}",
                extra={"action": action, "target": target},
            )
            self._history.append(result)
            return result

        # Execute action
        if self._simulation_mode:
            result = await self._simulate(action, target)
        else:
            result = await self._execute_real(action, target)

        self._history.append(result)
        return result

    def _is_protected(self, action: str, target: str) -> bool:
        """Check if the target is protected by the whitelist."""
        if action in ("BLOCK_IP", "NULL_ROUTE"):
            return self._whitelist.is_whitelisted(target)
        elif action == "RESTART_SERVICE":
            return self._whitelist.is_critical_service(target)
        elif action == "KILL_PROCESS":
            protected_processes = {"explorer.exe", "svchost.exe", "system", "python.exe", "cmd.exe", "powershell.exe", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}
            return target.lower() in protected_processes
        return False

    async def _simulate(self, action: str, target: str) -> ActionResult:
        """Simulate an action without real execution."""
        message = f"[SIMULATION] {action} executed against {target}"
        logger.info(message, extra={"action": action, "target": target})
        return ActionResult(
            success=True,
            action=action,
            target=target,
            message=message,
            simulated=True,
        )

    async def _execute_real(self, action: str, target: str) -> ActionResult:
        """
        Execute a real system action.

        WARNING: Only enabled when SIMULATION_MODE=False in config.
        """
        # Real implementation stubs — extend when ready for production
        handlers = {
            "BLOCK_IP": self._real_block_ip,
            "NULL_ROUTE": self._real_null_route,
            "RESTART_SERVICE": self._real_restart_service,
            "QUARANTINE": self._real_quarantine,
            "KILL_PROCESS": self._real_kill_process,
        }
        handler = handlers.get(action)
        if handler is None:
            return ActionResult(
                success=False, action=action, target=target,
                message=f"Unknown action type: {action}", simulated=False,
            )
        return await handler(target)

    async def _real_block_ip(self, target: str) -> ActionResult:
        """Block IP via Windows Firewall (netsh)."""
        import subprocess
        rule_name = f"GOZCU_BLOCK_{target}"
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={target}"
        ]
        
        try:
            # shell=True is generally not recommended, but for netsh it's sometimes easier.
            # We'll use a list of arguments which is safer.
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.critical(f"[REAL] BLOCK_IP: {target} blocked via Windows Firewall")
                return ActionResult(True, "BLOCK_IP", target, f"IP {target} blocked. Rule: {rule_name}", False)
            else:
                err_msg = stderr.decode().strip() or stdout.decode().strip()
                logger.error(f"Failed to block IP {target}: {err_msg}")
                return ActionResult(False, "BLOCK_IP", target, f"Failed: {err_msg}", False)
        except Exception as e:
            logger.error(f"Exception while blocking IP {target}: {e}")
            return ActionResult(False, "BLOCK_IP", target, f"Exception: {str(e)}", False)

    async def _real_null_route(self, target: str) -> ActionResult:
        """Null-route an IP. Placeholder for real implementation."""
        logger.critical(f"[REAL] NULL_ROUTE: {target}")
        return ActionResult(True, "NULL_ROUTE", target, f"IP {target} null-routed", False)

    async def _real_restart_service(self, target: str) -> ActionResult:
        """Restart a service. Placeholder for real implementation."""
        logger.critical(f"[REAL] RESTART_SERVICE: {target}")
        return ActionResult(True, "RESTART_SERVICE", target, f"Service {target} restarted", False)

    async def _real_quarantine(self, target: str) -> ActionResult:
        """Quarantine a resource. Placeholder for real implementation."""
        logger.critical(f"[REAL] QUARANTINE: {target}")
        return ActionResult(True, "QUARANTINE", target, f"Resource {target} quarantined", False)

    async def _real_kill_process(self, target: str) -> ActionResult:
        """Kill a process by image name via Windows taskkill."""
        import subprocess
        command = ["taskkill", "/F", "/IM", target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.critical(f"[REAL] KILL_PROCESS: {target} terminated via taskkill")
                return ActionResult(True, "KILL_PROCESS", target, f"Process {target} terminated.", False)
            else:
                err_msg = stderr.decode('cp1254', errors='replace').strip() or stdout.decode('cp1254', errors='replace').strip()
                logger.error(f"Failed to kill process {target}: {err_msg}")
                return ActionResult(False, "KILL_PROCESS", target, f"Failed: {err_msg}", False)
        except Exception as e:
            logger.error(f"Exception while killing process {target}: {e}")
            return ActionResult(False, "KILL_PROCESS", target, f"Exception: {str(e)}", False)

    def get_history(self) -> list[ActionResult]:
        """Return action execution history."""
        return list(self._history)
