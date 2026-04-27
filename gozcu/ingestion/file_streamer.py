"""
File Streamer.

Reads a log file line by line and simulates a continuous live stream
by introducing a delay between lines.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from gozcu.models.enums import SourceType

logger = logging.getLogger(__name__)

class FileStreamer:
    """Streams a file line by line with a delay."""
    
    def __init__(self, filepath: str | Path, source_type: SourceType, delay_seconds: float = 2.0):
        self.filepath = Path(filepath)
        self.source_type = source_type
        self.delay_seconds = delay_seconds
        
    async def stream_to_pipeline(self, pipeline) -> None:
        """Stream the file to the given pipeline continuously."""
        # hocaya not: sunumda gercek bir siber saldiri altindaymisiz gibi gostermek icin, elimizdeki ornek log dosyasini satir satir, aralara 2 saniye koyarak (delay) canli olarak sisteme akitiyorum.
        if not self.filepath.exists():
            logger.error(f"Cannot stream: File {self.filepath} not found.")
            return
            
        logger.info(f"Starting to stream from {self.filepath} (1 line / {self.delay_seconds}s)")
        
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        await pipeline.submit(raw_data=line, source_type=self.source_type, source_ip="0.0.0.0")
                        await asyncio.sleep(self.delay_seconds)
            logger.info("Finished streaming the entire file.")
        except Exception as e:
            logger.error(f"Error while streaming file {self.filepath}: {e}")
