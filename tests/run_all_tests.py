"""Run all tests with real pytest fixture isolation and honest skip reporting."""
from pathlib import Path
import sys
import pytest

if __name__ == "__main__":
    raise SystemExit(pytest.main([str(Path(__file__).resolve().parent), "-q", "-ra", *sys.argv[1:]]))
