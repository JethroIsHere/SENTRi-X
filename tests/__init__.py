"""Test suite for SENTRi-X ML pipeline corrections.
Provides lightweight test compatibility shims so tests can run with or without pytest.
"""

import sys
from types import ModuleType

try:
    import pytest
except ImportError:
    class RaisesContext:
        def __init__(self, expected_exception, match=None):
            self.expected = expected_exception
            self.match = match

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:
                raise AssertionError(f"Expected {self.expected.__name__} but no exception was raised.")
            if not issubclass(exc_type, self.expected):
                return False
            if self.match and self.match not in str(exc_val):
                raise AssertionError(f"Exception message '{exc_val}' does not match pattern '{self.match}'.")
            return True

    class Approx:
        def __init__(self, expected, abs=1e-6):
            self.expected = expected
            self.abs = abs

        def __eq__(self, other):
            return abs(float(self.expected) - float(other)) <= self.abs

        def __repr__(self):
            return f"approx({self.expected} ± {self.abs})"

    def fixture(fn):
        return fn

    pt = ModuleType("pytest")
    pt.raises = RaisesContext
    pt.approx = Approx
    pt.fixture = fixture
    sys.modules["pytest"] = pt
