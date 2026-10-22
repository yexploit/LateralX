"""Telemetry ingest package."""

from app.ingest.service import ingest_bytes, ingest_path, ingest_paths

__all__ = ["ingest_bytes", "ingest_path", "ingest_paths"]
