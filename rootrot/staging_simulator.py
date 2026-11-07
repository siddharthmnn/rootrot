"""model data chunking with synthetic bytes, kept in memory the whole time."""

import hashlib
from typing import Any


class staging_simulator:
    def __init__(
        self,
        logger: Any,
        chunk_size: int = 256,
        max_data_size: int = 1_000_000,
        max_chunks: int = 10_000,
    ) -> None:
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
            raise ValueError("chunk_size must be a positive integer")
        if isinstance(max_data_size, bool) or not isinstance(max_data_size, int) or max_data_size < 1:
            raise ValueError("max_data_size must be a positive integer")
        if isinstance(max_chunks, bool) or not isinstance(max_chunks, int) or max_chunks < 1:
            raise ValueError("max_chunks must be a positive integer")
        self.logger = logger
        self.chunk_size = chunk_size
        self.max_data_size = max_data_size
        self.max_chunks = max_chunks

    @staticmethod
    def verify_manifest(synthetic_data: bytes, result: dict[str, Any]) -> bool:
        if not isinstance(synthetic_data, bytes) or not isinstance(result, dict):
            return False
        if result.get("transmitted") is not False:
            return False
        if result.get("original_size") != len(synthetic_data):
            return False
        if result.get("sha256") != hashlib.sha256(synthetic_data).hexdigest():
            return False

        chunk_size = result.get("chunk_size")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
            return False
        expected_chunks = [
            synthetic_data[index:index + chunk_size]
            for index in range(0, len(synthetic_data), chunk_size)
        ]
        metadata = result.get("chunks")
        if result.get("chunk_count") != len(expected_chunks):
            return False
        if not isinstance(metadata, list) or len(metadata) != len(expected_chunks):
            return False

        for index, (chunk, item) in enumerate(zip(expected_chunks, metadata)):
            if not isinstance(item, dict):
                return False
            expected = {
                "index": index,
                "offset": index * chunk_size,
                "size": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
            }
            if item != expected:
                return False

        reassembled = b"".join(expected_chunks)
        return result.get("reassembled_sha256") == hashlib.sha256(reassembled).hexdigest()

    def run(self, synthetic_data: bytes) -> dict[str, Any]:
        if not isinstance(synthetic_data, bytes):
            raise TypeError("synthetic_data must be bytes")
        if len(synthetic_data) > self.max_data_size:
            raise ValueError("synthetic data exceeds the configured size limit")

        chunk_count = (len(synthetic_data) + self.chunk_size - 1) // self.chunk_size
        if chunk_count > self.max_chunks:
            raise ValueError("synthetic data would exceed the configured chunk limit")

        chunks = [
            synthetic_data[index:index + self.chunk_size]
            for index in range(0, len(synthetic_data), self.chunk_size)
        ]
        metadata = [
            {
                "index": index,
                "offset": index * self.chunk_size,
                "size": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
            }
            for index, chunk in enumerate(chunks)
        ]
        reassembled = b"".join(chunks)
        source_hash = hashlib.sha256(synthetic_data).hexdigest()
        reassembled_hash = hashlib.sha256(reassembled).hexdigest()
        manifest = {
            "original_size": len(synthetic_data),
            "chunk_size": self.chunk_size,
            "chunk_count": len(chunks),
            "sha256": source_hash,
            "reassembled_sha256": reassembled_hash,
            "chunks": metadata,
            "transmitted": False,
        }
        integrity_verified = (
            source_hash == reassembled_hash
            and self.verify_manifest(synthetic_data, manifest)
        )
        if not integrity_verified:
            raise RuntimeError("staging manifest failed its integrity check")

        result = {
            **manifest,
            "integrity_verified": integrity_verified,
        }
        self.logger.emit(
            "staging_simulator",
            "data.staged_in_memory",
            "warning",
            chunk_count=len(chunks),
            transmitted=False,
        )
        self.logger.emit(
            "staging_simulator",
            "data.staging_integrity_verified",
            "info",
            integrity_verified=True,
            original_size=len(synthetic_data),
        )
        return result
