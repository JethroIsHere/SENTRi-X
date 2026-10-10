"""Plain-English behavioral assessments for model-generated alerts.

SHAP/LIME explain the Random Forest component's feature contributions.
This module translates those signals into *what happened and why it's
suspicious* in plain English for thesis evaluation and operator review.

Design principles:
- Describe OBSERVED behavior, not assumed intent. Use "consistent with"
  / "resembles" / "characteristic of", never definitive attack labels
  from a single flow.
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


def _top_features(shap_values, feature_names=None, n=3):
    """Return the top-n features by absolute SHAP value, in plain English."""
    if not shap_values:
        return []
    # If shap_values is a list of dicts (e.g. [{'f': 'feat_name', 'v': val}, ...])
    if isinstance(shap_values, list) and shap_values and isinstance(shap_values[0], dict):
        extracted = []
        for item in shap_values:
            name = item.get('f') or item.get('feature') or ''
            val = item.get('v') if item.get('v') is not None else item.get('value', 0.0)
            try:
                extracted.append((FEATURE_NAMES.get(name, name), float(val)))
            except (ValueError, TypeError):
                continue
        return sorted(extracted, key=lambda x: abs(x[1]), reverse=True)[:n]

    if not feature_names:
        return []
    try:
        pairs = sorted(zip(feature_names, shap_values),
                       key=lambda x: abs(float(x[1])), reverse=True)[:n]
        return [(FEATURE_NAMES.get(name, name), float(val)) for name, val in pairs]
    except Exception:
        return []


def _behavioral_assessment(flow):
    """Describe only fields observed in this flow, without inferring intent."""
    observations = []
    dur = float(flow.get('duration', 0) or 0)
    spkts = int(flow.get('src_pkts', 0) or 0)
    dpkts = int(flow.get('dst_pkts', 0) or 0)
    sbytes = int(flow.get('src_bytes', 0) or 0)
    dbytes = int(flow.get('dst_bytes', 0) or 0)
    if int(flow.get('conn_state_S0', 0) or 0):
        observations.append("the sensor recorded an unanswered connection attempt")
    if int(flow.get('conn_state_REJ', 0) or 0):
        observations.append("the sensor recorded a rejected connection")
    if int(flow.get('conn_state_RSTO', 0) or 0):
        observations.append("the originator reset the connection")
    if dur > 0 and dur < 5 and spkts + dpkts > 20:
        observations.append(f"the observed packet rate was {(spkts + dpkts) / dur:.0f} packets/second")
    if sbytes > 100000 and dbytes < sbytes * 0.1:
        observations.append(f"the flow originator sent {sbytes:,} bytes and received {dbytes:,} bytes")
    return observations


def classify_attack_type(flow, shap_values=None, feature_names=None):
    """Return a heuristic flow-pattern label and its evidence.

    Kept under the existing API name for compatibility. RF/CNN predictions are
    binary. A single flow does not establish scanning, repeated authentication,
    service exhaustion, exfiltration, or a compromised encrypted channel.
    SHAP values are not used to infer an attack subtype.
    """
    dur = float(flow.get('duration', 0) or 0)
    spkts = int(flow.get('src_pkts', 0) or 0)
    dpkts = int(flow.get('dst_pkts', 0) or 0)
    sbytes = int(flow.get('src_bytes', 0) or 0)
    dbytes = int(flow.get('dst_bytes', 0) or 0)
    dport = flow.get('dst_port')
    try:
        dport = int(dport) if dport is not None else None
    except (ValueError, TypeError):
        dport = None
    total_pkts = spkts + dpkts
    s0 = int(flow.get('conn_state_S0', 0) or 0)
    rej = int(flow.get('conn_state_REJ', 0) or 0)
    rsto = int(flow.get('conn_state_RSTO', 0) or 0)
    sf = int(flow.get('conn_state_SF', 0) or 0)

    if (s0 > 0 or rej > 0) and sf == 0 and total_pkts <= 5 and dur < 5:
        return (
            "unanswered or rejected connection (heuristic)",
            "a short, low-packet connection did not complete; scanning requires "
            "correlated attempts across ports or hosts, and benign failures can look similar"
        )
    if dur > 0 and dur < 10 and total_pkts / dur > 100:
        return (
            "high packet rate (heuristic)",
            f"the observed rate was {total_pkts / dur:.0f} packets/second; "
            "a small duration can inflate this rate, and service impact is unverified"
        )
    if dur > 0 and dur < 5 and sbytes > 500000:
        return (
            "large transfer over a short interval (heuristic)",
            f"the originator sent {sbytes:,} bytes in {dur:.1f} seconds; "
            "this alone does not establish bandwidth exhaustion"
        )
    services = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC', 8088: 'lab HTTP'}
    if dport in services and (rsto > 0 or rej > 0):
        return (
            "reset or rejected service connection (heuristic)",
            f"this connection to port {dport} ({services[dport]}) was reset or rejected; "
            "repeated password attempts and authentication outcomes require service logs"
        )
    if sbytes > 100000 and dbytes < sbytes * 0.1 and sf > 0:
        return (
            "asymmetric data transfer (heuristic)",
            f"the originator sent {sbytes:,} bytes and received {dbytes:,} bytes; "
            "the data content and transfer purpose are unknown"
        )
    # SNI is not captured by the current edge sensor. Missing metadata is not
    # evidence of TLS, command-and-control, or tunneling.
    return (
        "model-flagged flow anomaly",
        "the binary model flagged this flow; the available flow fields do not "
        "establish a specific attack subtype or a per-device learned baseline"
    )


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
    """Generate a plain-English assessment of a model-generated alert.

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

    # 2. What kind of attack this resembles
    attack_type, reasoning = classify_attack_type(flow, shap_values, feature_names)
    parts.append(
        f"The separate heuristic assessment is {attack_type}: {reasoning}. "
        "This is not an RF/CNN attack-subtype prediction."
    )

    # 3. Why it's suspicious (behavioral details)
    observations = _behavioral_assessment(flow)
    if observations:
        parts.append(
            "Observed flow details: " +
            "; ".join(observations) + "."
        )

    # 4. What the model saw (top features in plain English)
    top = _top_features(shap_values, feature_names)
    if top:
        feat_text = ", ".join(
            f"{name} ({'supports' if val > 0 else 'opposes' if val < 0 else 'is neutral toward'} the RF attack-class output)"
            for name, val in top
        )
        parts.append(
            f"The {model_type} model flagged this flow with "
            f"{_confidence_text(confidence)} model confidence. The separate RF "
            f"feature explanation highlights: {feat_text}. "
            "RF SHAP does not explain the CNN or the fused hybrid output."
        )
    else:
        parts.append(
            f"The {model_type} model flagged this flow with "
            f"{_confidence_text(confidence)} confidence."
        )

    # 5. Honest scope limitation
    parts.append(
        "This assessment describes a single network flow. "
        "Model confidence is not proof of an attack. Confirmation requires "
        "correlating flows over time with independent packet or service evidence."
    )

    return " ".join(parts)

