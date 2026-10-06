"""Plain-English attack narratives for confirmed alerts.

SHAP/LIME/RIPPER explain *which features* drove the model's decision.
This module translates those signals into *what happened and why it's
suspicious* in plain English for thesis evaluation and operator review.

Design principles:
- Describe OBSERVED behavior, not assumed intent. Use "consistent with"
  / "resembles" / "characteristic of", never definitive attack labels
  unless the pattern is unambiguous.
- Ground every claim in actual flow fields or SHAP-ranked features.
- Never invent details (IPs, ports, timings) not present in the data.
"""

# Human-readable names for model features
FEATURE_NAMES = {
    'duration': 'connection duration',
    'src_bytes': 'bytes sent by the device',
    'dst_bytes': 'bytes received by the device',
    'missed_bytes': 'missed bytes',
    'src_pkts': 'packets sent by the device',
    'src_ip_bytes': 'IP-layer bytes sent',
    'dst_pkts': 'packets received by the device',
    'dst_ip_bytes': 'IP-layer bytes received',
    'dns_qclass': 'DNS query class',
    'dns_qtype': 'DNS query type',
    'dns_rcode': 'DNS response code',
    'http_request_body_len': 'HTTP request body size',
    'http_response_body_len': 'HTTP response body size',
    'http_status_code': 'HTTP status code',
    'proto_tcp': 'TCP protocol',
    'proto_udp': 'UDP protocol',
    'conn_state_REJ': 'rejected connections',
    'conn_state_RSTO': 'reset connections',
    'conn_state_RSTOS0': 'one-sided resets',
    'conn_state_RSTR': 'responder resets',
    'conn_state_RSTRH': 'responder reset halves',
    'conn_state_S0': 'unanswered connection attempts',
    'conn_state_S1': 'half-open connections',
    'conn_state_S2': 'half-closed connections',
    'conn_state_S3': 'fully established then closed',
    'conn_state_SF': 'cleanly completed connections',
    'conn_state_SH': 'originator half-close',
    'conn_state_SHR': 'responder half-close',
}


def _describe_flow(flow):
    """One-sentence factual description of the flow."""
    src = flow.get('src_ip', 'unknown')
    dst = flow.get('dst_ip', 'unknown')
    sport = flow.get('src_port', '?')
    dport = flow.get('dst_port', '?')
    proto = flow.get('proto', 'unknown')
    dur = flow.get('duration', 0)
    spkts = flow.get('src_pkts', 0)
    dpkts = flow.get('dst_pkts', 0)
    sbytes = flow.get('src_bytes', 0)
    dbytes = flow.get('dst_bytes', 0)
    device = flow.get('device_name', 'unknown device')

    parts = [
        f"Device '{device}' ({src}) exchanged {spkts + dpkts} {proto} packets "
        f"with {dst}:{dport} over {dur:.1f} seconds"
    ]
    if sbytes or dbytes:
        parts.append(f"({sbytes} bytes sent, {dbytes} bytes received)")
    sni = flow.get('sni')
    if sni:
        parts.append(f"using TLS with server name '{sni}'")
    return " ".join(parts) + "."


def _top_features(shap_values, feature_names, n=3):
    """Return the top-n features by absolute SHAP value, in plain English."""
    if not shap_values or not feature_names:
        return []
    pairs = sorted(zip(feature_names, shap_values),
                   key=lambda x: abs(x[1]), reverse=True)[:n]
    return [(FEATURE_NAMES.get(name, name), val) for name, val in pairs]


def _behavioral_assessment(flow):
    """Map flow characteristics to plain-English behavioral observations."""
    observations = []

    dur = float(flow.get('duration', 0) or 0)
    spkts = int(flow.get('src_pkts', 0) or 0)
    dpkts = int(flow.get('dst_pkts', 0) or 0)
    sbytes = int(flow.get('src_bytes', 0) or 0)
    dbytes = int(flow.get('dst_bytes', 0) or 0)
    dport = flow.get('dst_port')
    proto = str(flow.get('proto', '')).upper()
    sni = flow.get('sni')

    total_pkts = spkts + dpkts

    # Short duration, few packets, connection not cleanly closed
    s0 = int(flow.get('conn_state_S0', 0) or 0)
    rej = int(flow.get('conn_state_REJ', 0) or 0)
    rsto = int(flow.get('conn_state_RSTO', 0) or 0)
    sf = int(flow.get('conn_state_SF', 0) or 0)

    if s0 > 0 and sf == 0:
        observations.append(
            "the connection attempt went unanswered (no response from the target)"
        )
    if rej > 0:
        observations.append("the target actively rejected the connection")
    if rsto > 0:
        observations.append("the connection was reset mid-handshake")

    # High packet rate in short time
    if dur > 0 and dur < 5 and total_pkts > 20:
        rate = total_pkts / dur
        observations.append(
            f"a high packet rate of {rate:.0f} packets/second, "
            "which is unusual for normal IoT device communication"
        )

    # Large outbound transfer
    if sbytes > 100000 and dbytes < sbytes * 0.1:
        observations.append(
            f"a large one-directional data transfer ({sbytes:,} bytes sent "
            "with minimal response), which can indicate data exfiltration"
        )

    # TLS without SNI or unusual port
    if proto == 'TCP' and dport == 443 and not sni:
        observations.append(
            "encrypted traffic on the HTTPS port without a visible server name, "
            "which is atypical for standard IoT cloud connections"
        )

    # Common attack target ports
    sensitive_ports = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 445: 'SMB'}
    if dport in sensitive_ports:
        observations.append(
            f"the target port ({dport}, {sensitive_ports[dport]}) is a "
            "common target for unauthorized access attempts"
        )

    return observations


def _confidence_text(confidence):
    """Plain-English confidence description."""
    pct = confidence * 100
    if pct >= 95:
        return f"very high ({pct:.1f}%)"
    elif pct >= 85:
        return f"high ({pct:.1f}%)"
    elif pct >= 70:
        return f"moderate ({pct:.1f}%)"
    else:
        return f"low ({pct:.1f}%)"


def generate_attack_narrative(flow, shap_values=None, feature_names=None,
                              confidence=0.0, model_type='unknown'):
    """Generate a plain-English summary of a confirmed attack.

    Args:
        flow: dict of flow fields (src_ip, dst_ip, ports, proto, bytes, etc.)
        shap_values: list of SHAP values aligned with feature_names
        feature_names: list of feature names
        confidence: model confidence (0-1)
        model_type: which model made the decision

    Returns:
        A plain-English paragraph string.
    """
    parts = []

    # 1. What happened (factual)
    parts.append(_describe_flow(flow))

    # 2. Why it's suspicious (behavioral)
    observations = _behavioral_assessment(flow)
    if observations:
        parts.append(
            "This flow is suspicious because " +
            "; ".join(observations) + "."
        )

    # 3. What the model saw (top features in plain English)
    top = _top_features(shap_values, feature_names)
    if top:
        feat_text = ", ".join(
            f"{name} ({'increased' if val > 0 else 'decreased'} attack likelihood)"
            for name, val in top
        )
        parts.append(
            f"The {model_type} model flagged this flow with "
            f"{_confidence_text(confidence)} confidence, driven primarily by: "
            f"{feat_text}."
        )
    else:
        parts.append(
            f"The {model_type} model flagged this flow with "
            f"{_confidence_text(confidence)} confidence."
        )

    # 4. Honest scope limitation
    parts.append(
        "This assessment describes a single network flow. "
        "A definitive attack determination requires correlating "
        "multiple flows over time."
    )

    return " ".join(parts)
