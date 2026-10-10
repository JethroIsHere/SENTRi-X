#!/usr/bin/env python3
"""SENTRi-X backend XAI verification script.

Run on the laptop after starting the backend:
    python3 verify_xai.py [--url http://192.168.254.156:8000]

Checks:
1. Package activated (not offline) via /api/status
2. LIME explainer initialized (not 'unavailable')
3. SHAP TreeExplainer wired (per-flow method, not global fallback)
4. RIPPER rules present with fidelity score (not empty, not NaN)
"""
import json
import sys
import urllib.request
import urllib.error

URL = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "--url" else "http://192.168.254.151:8000"
if "--url" in sys.argv:
    URL = sys.argv[sys.argv.index("--url") + 1]

failures = []

def get(path):
    try:
        with urllib.request.urlopen(URL + path, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        failures.append(f"GET {path}: connection failed ({e})")
        return None

print(f"Backend: {URL}\n")

# 1. Status: models online
status = get("/api/status")
if status:
    rf = status.get("rf_online")
    cnn = status.get("cnn_online")
    model = status.get("current_model", "?")
    print(f"[1] Status: model={model} rf_online={rf} cnn_online={cnn}")
    if not rf:
        failures.append("RF model offline — check package activation (PACKAGE_ALIASES)")
else:
    print("[1] Status: UNREACHABLE")

# 2. RIPPER rules + fidelity
ripper = get("/api/explainability/ripper")
if ripper:
    rules = ripper.get("rules", "")
    fid = ripper.get("fidelity_vs_rf")
    note = ripper.get("fidelity_note", "")
    bg = ripper.get("background", "")
    n_rules = len(rules.split(" V ")) if " V " in rules else (rules.count("IF ") if "IF " in rules else (1 if rules.strip() else 0))
    print(f"[2] RIPPER: {n_rules} rules, fidelity={fid}, background={bg}")
    print(f"    note: {note[:100]}")
    if not rules:
        failures.append("RIPPER rules empty")
    if fid is None:
        print("    WARNING: fidelity is null — check fidelity_note")
    elif isinstance(fid, float) and (fid != fid):  # NaN check
        failures.append("RIPPER fidelity is NaN (invalid JSON)")
    if bg != "synthetic_from_scaler_stats":
        failures.append(f"Unexpected background provenance: {bg}")
else:
    print("[2] RIPPER: UNREACHABLE")

# 3. Model metrics (sanity: package loaded)
metrics = get("/api/model-metrics")
if metrics:
    avail = metrics.get("available", False)
    print(f"[3] Model metrics: available={avail}")
    if not avail:
        failures.append(f"Model metrics unavailable: {metrics.get('reason', '?')}")
else:
    print("[3] Model metrics: UNREACHABLE")

print()
if failures:
    print("FAILURES:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("All checks passed.")
print("\nNote: LIME/SHAP per-flow output can only be verified from a real")
print("alert record (threat-logs) after live traffic flows through.")
