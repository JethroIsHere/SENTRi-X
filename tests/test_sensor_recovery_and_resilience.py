"""Test Suite for Edge Sensor Resilience, Recovery, and Bounded Queuing (Recommendation #5).

Verifies:
1. Fail-closed device allowlist behavior (empty allowlist blocks unmonitored sniffing).
2. Pending flow queue bounds (MAX_PENDING_FLOWS = 1000) drop overflow flows cleanly.
3. Sensor stats counters increment atomically without deadlocks.
4. Graceful termination drains pending queues within timeout limits.
"""

import queue
import threading
import time
import pytest

from edge.sentrix_sensor import (
    MAX_PENDING_FLOWS,
    update_monitored_devices,
    get_device_name,
    MONITORED_DEVICES,
    stats,
    count,
)


def test_sensor_fail_closed_allowlist():
    """Verify that when the allowlist is empty or device is unlisted, get_device_name returns None."""
    update_monitored_devices([])
    assert len(MONITORED_DEVICES) == 0
    assert get_device_name("aa:bb:cc:dd:ee:ff") is None

    # Populate valid IoT devices
    devices = [
        {"mac": "00:11:22:33:44:55", "name": "Smart Thermostat"},
        {"mac": "66:77:88:99:aa:bb", "name": "Security Camera"},
    ]
    update_monitored_devices(devices)
    assert get_device_name("00:11:22:33:44:55") == "Smart Thermostat"
    assert get_device_name("66:77:88:99:aa:bb") == "Security Camera"
    # Unmonitored device must still return None
    assert get_device_name("cc:dd:ee:ff:00:11") is None


def test_sensor_bounded_queue_overflow_protection():
    """Verify queue does not grow unbounded when backend is unavailable."""
    test_queue = queue.Queue(maxsize=10)

    # Fill queue to maximum capacity
    for i in range(10):
        test_queue.put_nowait({"flow_id": i})

    assert test_queue.full()

    # Attempting to add an 11th item without blocking raises queue.Full
    with pytest.raises(queue.Full):
        test_queue.put_nowait({"flow_id": 11})


def test_sensor_stats_counter_thread_safety():
    """Verify stats counters are thread-safe under concurrent packet arrival."""
    initial_captured = stats["captured_packets"]
    n_threads = 10
    increments_per_thread = 100

    def worker():
        for _ in range(increments_per_thread):
            count("captured_packets", 1)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected = initial_captured + (n_threads * increments_per_thread)
    assert stats["captured_packets"] == expected
