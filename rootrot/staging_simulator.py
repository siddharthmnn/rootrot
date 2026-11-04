"""model data chunking with synthetic bytes, kept in memory the whole time."""

import hashlib
from typing import Any


class staging_simulator:
    def __init__(self, logger: Any, chunk_size: int = 256) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")

        self.logger = logger
        self.chunk_size = chunk_size

    def run(self, synthetic_data: bytes) -> dict[str, Any]:
        chunks = [
            synthetic_data[index:index + self.chunk_size]
            for index in range(0, len(synthetic_data), self.chunk_size)
        ]
        metadata = [
            {
                "index": index,
                "size": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
            }
            for index, chunk in enumerate(chunks)
        ]

        result = {
            "original_size": len(synthetic_data),
            "chunk_count": len(chunks),
            "chunks": metadata,
            "transmitted": False,
        }
        self.logger.emit(
            "staging_simulator",
            "data.staged_in_memory",
            "warning",
            chunk_count=len(chunks),
            transmitted=False,
        )
        return result
