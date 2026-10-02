"""Isolate every backend test from saved hardware records."""
import os
import tempfile
from pathlib import Path

_database_directory = tempfile.TemporaryDirectory(prefix="sentrix-tests-")
os.environ["SENTRIX_DB_PATH"] = str(Path(_database_directory.name) / "isolated.sqlite")
os.environ.setdefault("TF_NUM_INTRAOP_THREADS", "1")
os.environ.setdefault("TF_NUM_INTEROP_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")


def pytest_sessionfinish(session, exitstatus):
    _database_directory.cleanup()
