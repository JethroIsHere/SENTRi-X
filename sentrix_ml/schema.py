"""Canonical feature schema for SENTRi-X inference and training.

Every consumer — notebooks, backend, sensor, evaluation — must use
EXPECTED_FEATURES as the single source of truth for feature ordering.

SCHEMA_VERSION tracks breaking changes.  When a field is added, removed,
or its semantics change, bump the version and mark old model packages
incompatible.
"""

from sentrix_ml import SCHEMA_VERSION

# ── 28-feature ordered contract ─────────────────────────────────────
# Groups:
#   [0-13]  Numeric flow features (continuous)
#   [14-15] Protocol one-hot   (binary)
#   [16-27] Connection-state one-hot (binary)

EXPECTED_FEATURES: list[str] = [
    # --- Continuous flow features ---
    "duration",                  # Flow duration in seconds
    "src_bytes",                 # Bytes sent by the source (originator payload)
    "dst_bytes",                 # Bytes sent by the destination (responder payload)
    "missed_bytes",              # Bytes missed / gaps in the connection
    "src_pkts",                  # Packets sent by the source
    "src_ip_bytes",              # Total IP-level bytes from source (incl. headers)
    "dst_pkts",                  # Packets sent by the destination
    "dst_ip_bytes",              # Total IP-level bytes from destination (incl. headers)
    "dns_qclass",                # DNS query class (0 if not DNS)
    "dns_qtype",                 # DNS query type  (0 if not DNS)
    "dns_rcode",                 # DNS response code (0 if not DNS)
    "http_request_body_len",     # HTTP request body length (0 if not HTTP)
    "http_response_body_len",    # HTTP response body length (0 if not HTTP)
    "http_status_code",          # HTTP status code (0 if not HTTP)
    # --- Protocol one-hot ---
    "proto_tcp",                 # 1 if protocol is TCP
    "proto_udp",                 # 1 if protocol is UDP
    # --- Connection state one-hot ---
    "conn_state_REJ",
    "conn_state_RSTO",
    "conn_state_RSTOS0",
    "conn_state_RSTR",
    "conn_state_RSTRH",
    "conn_state_S0",
    "conn_state_S1",
    "conn_state_S2",
    "conn_state_S3",
    "conn_state_SF",
    "conn_state_SH",
    "conn_state_SHR",
]

NUM_FEATURES = len(EXPECTED_FEATURES)  # 28

# Core flow features that MUST be present and valid numeric (non-negative, finite)
REQUIRED_NUMERIC_FEATURES: list[str] = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_pkts",
    "dst_pkts",
]

# Optional flow measurements: if missing, empty, or '-' in raw data, impute with 0.0
OPTIONAL_NUMERIC_FEATURES: list[str] = [
    "missed_bytes",
    "src_ip_bytes",
    "dst_ip_bytes",
    "dns_qclass",
    "dns_qtype",
    "dns_rcode",
    "http_request_body_len",
    "http_response_body_len",
    "http_status_code",
]

# Indices and groups for convenience
NUMERIC_FEATURE_NAMES: list[str] = REQUIRED_NUMERIC_FEATURES + OPTIONAL_NUMERIC_FEATURES
PROTO_FEATURE_NAMES: list[str] = EXPECTED_FEATURES[14:16]
CONN_STATE_FEATURE_NAMES: list[str] = EXPECTED_FEATURES[16:]

# Known protocol vocabulary (for one-hot encoding from text)
PROTO_VOCAB: list[str] = ["tcp", "udp"]

# Known connection-state vocabulary (Zeek/Bro states)
CONN_STATE_VOCAB: list[str] = [
    "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH",
    "S0", "S1", "S2", "S3", "SF", "SH", "SHR",
]

# Classification semantics
CLASS_MAPPING: dict[str, str] = {"0": "Benign", "1": "Attack"}
ATTACK_CLASS_INDEX = 1

# ── Field documentation ─────────────────────────────────────────────
FIELD_DOCS: dict[str, dict] = {
    "duration": {
        "unit": "seconds",
        "source": "Zeek conn.log / CICFlowMeter flow_duration",
        "missing_policy": "0.0 (instantaneous flow)",
        "notes": "CIC-IDS2017 records microseconds; adapter converts to seconds.",
    },
    "src_bytes": {
        "unit": "bytes (originator payload)",
        "source": "Zeek orig_bytes / CIC Total Length of Fwd Packets",
        "missing_policy": "0",
        "notes": "Zeek: payload bytes only.  CIC: total length of forward packets.",
    },
    "dst_bytes": {
        "unit": "bytes (responder payload)",
        "source": "Zeek resp_bytes / CIC Total Length of Bwd Packets",
        "missing_policy": "0",
    },
    "missed_bytes": {
        "unit": "bytes",
        "source": "Zeek missed_bytes",
        "missing_policy": "0",
        "notes": "Not available in CIC-IDS2017 or BoT-IoT; filled with 0.",
    },
    "src_pkts": {
        "unit": "packet count",
        "source": "Zeek orig_pkts / CIC Total Fwd Packets / BoT spkts",
        "missing_policy": "0",
    },
    "src_ip_bytes": {
        "unit": "bytes (total IP-level from source)",
        "source": "Zeek orig_ip_bytes",
        "missing_policy": "0",
        "notes": ("BoT-IoT maps TnBPSrcIP here.  TnBPSrcIP is 'Total Number of "
                  "Bytes Per Source IP' — a per-IP aggregate, NOT per-flow IP bytes. "
                  "This is a KNOWN SEMANTIC MISMATCH flagged for review."),
    },
    "dst_ip_bytes": {
        "unit": "bytes (total IP-level from destination)",
        "source": "Zeek resp_ip_bytes",
        "missing_policy": "0",
        "notes": ("BoT-IoT maps TnBPDstIP here.  Same aggregate caveat as "
                  "src_ip_bytes."),
    },
    "dns_qclass":  {"unit": "integer code", "missing_policy": "0"},
    "dns_qtype":   {"unit": "integer code", "missing_policy": "0"},
    "dns_rcode":   {"unit": "integer code", "missing_policy": "0"},
    "http_request_body_len":  {"unit": "bytes", "missing_policy": "0"},
    "http_response_body_len": {"unit": "bytes", "missing_policy": "0"},
    "http_status_code":       {"unit": "HTTP status integer", "missing_policy": "0"},
    "proto_tcp":   {"unit": "binary 0/1", "source": "one-hot from proto field"},
    "proto_udp":   {"unit": "binary 0/1", "source": "one-hot from proto field"},
}
for cs in CONN_STATE_VOCAB:
    FIELD_DOCS[f"conn_state_{cs}"] = {
        "unit": "binary 0/1",
        "source": "one-hot from conn_state field",
    }

# ── Semantic flags for unresolved mappings ───────────────────────────
UNRESOLVED_MAPPINGS: list[str] = [
    "BoT-IoT TnBPSrcIP->src_ip_bytes: per-IP aggregate vs per-flow IP bytes",
    "BoT-IoT TnBPDstIP->dst_ip_bytes: same aggregate caveat",
    "CIC-IDS2017 duration: microseconds in raw CSV, converted to seconds by adapter",
    "CIC-IDS2017 proto/conn_state: injected as 'other'/'OTH' - actual protocol unavailable",
    "Pi sensor byte semantics: pending verification of current sentrix_sensor.py",
]
