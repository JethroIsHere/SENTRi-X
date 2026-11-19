# Appendix A — Expert review instrument

The 28 prompts below are the administered items, grouped by the nine product-quality characteristics. Each uses a 1–5 agreement rating and allows an evidence or issue comment. The operational explanations cover the Random Forest; the questionnaire mentions RIPPER in EFS03, but RIPPER was experimental, and this item does not establish that the CNN or complete Hybrid was explained.

## Functional Suitability

**EFS01** — All dashboard and API functions required for monitoring, alerting, and explanation are implemented and reachable.

**EFS02** — Alert records contain the data fields required for triage (timestamp, device identity, flow features, model scores).

**EFS03** — XAI outputs (SHAP, LIME, RIPPER) are generated from the active model package, not from stale or placeholder artifacts.

## Performance Efficiency

**EPE01** — Dashboard page loads and API responses meet acceptable timing under expected load (record measured timings as evidence).

**EPE02** — Pi sensor CPU and memory usage stay within bounds during continuous capture.

**EPE03** — The backend ingests the expected flow rate without unbounded queue growth or dropped submissions.

## Compatibility

**ECO01** — Dashboard functions work correctly across the target browsers.

**ECO02** — The sensor-to-backend API contract tolerates version mismatch gracefully (no silent data corruption.

## Interaction Capability

**EIC01** — Critical states (sensor offline, model inactive, stale data) are visually distinct and unmissable.

**EIC02** — Destructive or hard-to-reverse actions (device removal, configuration changes) have confirmation or are recoverable.

**EIC03** — Terminology is consistent across the dashboard, API responses, and documentation.

## Reliability

**ERL01** — The sensor reconnects and resumes capture after a network interruption without manual intervention.

**ERL02** — The backend restarts into a consistent state (no database corruption, configuration preserved).

**ERL03** — Failures are logged with enough detail (timestamp, component, cause) to support diagnosis.

## Security

**ESE01** — API endpoints enforce appropriate access control; administrative actions are not available unauthenticated.

**ESE02** — User-supplied inputs (MAC addresses, device names, configuration values) are validated server-side.

**ESE03** — Credentials and secrets are not hardcoded in tracked code and are not exposed in logs or error messages.

**ESE04** — Significant actions (device add/remove, configuration changes) are attributable through an audit trail.

**ESE05** — Data in transit between sensor and backend is protected at a level appropriate to the deployment.

## Maintainability

**EMA01** — Code is organized into modules with clear responsibilities (sensor, API, XAI, data layer).

**EMA02** — Automated tests cover critical paths (packaging validation, API behavior, sensor logic).

**EMA03** — Site-specific values (IPs, MACs, paths) are externalized to configuration, not hardcoded in tracked code.

## Flexibility

**EFL01** — The system can be installed on a fresh environment by following the documented steps.

**EFL02** — Model packages can be replaced or upgraded without code changes (package activation mechanism).

**EFL03** — Sensor configuration adapts to different network environments through configuration, not code edits.

## Safety

**ESA01** — The sensor operates in monitor-only mode: it does not inject packets or take active response actions on the network.

**ESA02** — Failure of the IDS (sensor or backend) does not disrupt the monitored network's normal traffic.

**ESA03** — Known limitations (synthetic XAI background rows, detection scope, model weaknesses such as CIC-IDS2017 CNN recall) are disclosed in the interface or documentation.

[Aggregate results by item](C-evaluation.md)
