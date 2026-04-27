"""
Whitelist Manager.

Protects critical infrastructure IPs, subnets, and services from
being targeted by automated mitigation actions. The whitelist is
loaded from a JSON file at startup and is immutable at runtime.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import List, Set

logger = logging.getLogger(__name__)


class WhitelistManager:
    """
    Manages the critical infrastructure whitelist.

    Checks IPs against exact matches and CIDR subnet ranges.
    Checks service names against a protected services list.
    """

    def __init__(self) -> None:
        self._ips: Set[str] = set()
        self._subnets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._services: Set[str] = set()
        self._loaded = False

    def load(self, path: str | Path) -> None:
        """Load whitelist from a JSON file."""
        path = Path(path)
        if not path.exists():
            logger.critical(f"Whitelist file not found: {path}")
            raise FileNotFoundError(f"Whitelist file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.critical(f"Whitelist JSON parse error: {e}")
            raise

        # Load IPs
        self._ips = {ip.strip() for ip in data.get("ips", []) if ip.strip()}

        # Load subnets
        self._subnets = []
        for subnet_str in data.get("subnets", []):
            try:
                self._subnets.append(ipaddress.ip_network(subnet_str.strip(), strict=False))
            except ValueError as e:
                logger.warning(f"Invalid subnet in whitelist: {subnet_str} — {e}")

        # Load services
        self._services = {s.strip().lower() for s in data.get("services", []) if s.strip()}

        self._loaded = True
        logger.info(
            f"Whitelist loaded: {len(self._ips)} IPs, "
            f"{len(self._subnets)} subnets, {len(self._services)} services"
        )

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is protected by the whitelist."""
        # hocaya not: eger whitelist dosyasi bir sekilde yuklenemediyse guvenlik amaciyla her seyi korunuyor (protected) sayiyorum. yoksa sistem yanlislikla kendi kendini vurabilir.
        if not self._loaded:
            logger.warning("Whitelist not loaded — defaulting to PROTECTED")
            return True  # Fail-safe: if whitelist isn't loaded, protect everything

        ip = ip.strip()

        # Exact match
        if ip in self._ips:
            return True

        # Subnet match
        try:
            addr = ipaddress.ip_address(ip)
            for subnet in self._subnets:
                if addr in subnet:
                    return True
        except ValueError:
            logger.debug(f"Invalid IP address for whitelist check: {ip}")
            return False

        return False

    def is_critical_service(self, service_name: str) -> bool:
        """Check if a service name is on the protected list."""
        if not self._loaded:
            return True  # Fail-safe
        return service_name.strip().lower() in self._services

    def get_summary(self) -> dict:
        """Return whitelist summary for dashboard."""
        return {
            "loaded": self._loaded,
            "ip_count": len(self._ips),
            "subnet_count": len(self._subnets),
            "service_count": len(self._services),
        }
