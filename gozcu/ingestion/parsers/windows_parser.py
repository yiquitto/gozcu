"""
Windows Event Log Parser.

Parses Windows Event Log entries in XML format (as exported from .evtx files
or received via Windows Event Forwarding). Extracts key fields into a
normalized dictionary.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Windows Event Log XML namespace
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Simple key-value fallback pattern for non-XML text logs
_KV_RE = re.compile(r"EventID[=:]\s*(\d+)", re.IGNORECASE)


class WindowsEventParser:
    """Parses Windows Event Log XML entries into normalized dicts."""

    @staticmethod
    def parse(raw_xml: str) -> Optional[Dict[str, Any]]:
        """
        Parse a Windows Event Log XML entry.

        Returns a normalized dict or None if parsing fails entirely.
        """
        if not raw_xml or not raw_xml.strip():
            return None

        raw_xml = raw_xml.strip()

        # Try XML parsing
        try:
            root = ET.fromstring(raw_xml)
            return WindowsEventParser._parse_xml(root)
        except ET.ParseError:
            pass

        # Fallback: try to extract basic info from text
        return WindowsEventParser._parse_text_fallback(raw_xml)

    @staticmethod
    def _parse_xml(root: ET.Element) -> Dict[str, Any]:
        """Parse a proper XML Event element."""
        system = root.find("e:System", _NS) or root.find("System")

        result: Dict[str, Any] = {
            "format": "WINDOWS_XML",
            "event_id": "",
            "provider": "",
            "level": -1,
            "level_name": "UNKNOWN",
            "timestamp": "",
            "computer": "",
            "channel": "",
            "message": "",
        }

        if system is not None:
            # EventID
            eid_el = system.find("e:EventID", _NS) or system.find("EventID")
            if eid_el is not None and eid_el.text:
                result["event_id"] = eid_el.text.strip()

            # Provider
            prov_el = system.find("e:Provider", _NS) or system.find("Provider")
            if prov_el is not None:
                result["provider"] = prov_el.get("Name", "")

            # Level
            lvl_el = system.find("e:Level", _NS) or system.find("Level")
            if lvl_el is not None and lvl_el.text:
                try:
                    level = int(lvl_el.text)
                    result["level"] = level
                    result["level_name"] = _LEVEL_MAP.get(level, "UNKNOWN")
                except ValueError:
                    pass

            # TimeCreated
            tc_el = system.find("e:TimeCreated", _NS) or system.find("TimeCreated")
            if tc_el is not None:
                result["timestamp"] = tc_el.get("SystemTime", "")

            # Computer
            comp_el = system.find("e:Computer", _NS) or system.find("Computer")
            if comp_el is not None and comp_el.text:
                result["computer"] = comp_el.text.strip()

            # Channel
            ch_el = system.find("e:Channel", _NS) or system.find("Channel")
            if ch_el is not None and ch_el.text:
                result["channel"] = ch_el.text.strip()

        # EventData — extract all Data elements as message
        event_data = root.find("e:EventData", _NS) or root.find("EventData")
        if event_data is not None:
            data_parts = []
            for data_el in event_data:
                name = data_el.get("Name", "")
                value = data_el.text or ""
                if name:
                    data_parts.append(f"{name}={value}")
                elif value:
                    data_parts.append(value)
            result["message"] = "; ".join(data_parts)

        return result

    @staticmethod
    def _parse_text_fallback(raw_text: str) -> Dict[str, Any]:
        """Best-effort parsing for non-XML Windows event text."""
        result: Dict[str, Any] = {
            "format": "WINDOWS_TEXT",
            "event_id": "",
            "provider": "",
            "level": -1,
            "level_name": "UNKNOWN",
            "timestamp": "",
            "computer": "",
            "channel": "",
            "message": raw_text,
        }

        match = _KV_RE.search(raw_text)
        if match:
            result["event_id"] = match.group(1)

        return result


# Windows Event Level mapping
_LEVEL_MAP = {
    0: "LOG_ALWAYS",
    1: "CRITICAL",
    2: "ERROR",
    3: "WARNING",
    4: "INFORMATION",
    5: "VERBOSE",
}
