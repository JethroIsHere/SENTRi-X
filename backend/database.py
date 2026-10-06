"""SQLite storage with additive migrations that preserve existing records."""
import json
from contextlib import closing
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("SENTRIX_DB_PATH", os.path.join(os.path.dirname(__file__), '..', 'data', 'sentrix.db'))


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def get_db_connection():
    target_path = os.environ.get("SENTRIX_DB_PATH", DB_PATH)
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    conn = sqlite3.connect(target_path, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=15000')
    return conn


def init_db():
    with closing(get_db_connection()) as conn, conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS Network_Flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP NOT NULL,
            sensor_id TEXT DEFAULT 'rpi3b-edge-01', src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL, proto TEXT DEFAULT 'TCP', duration REAL DEFAULT 0,
            src_bytes INTEGER DEFAULT 0, dst_bytes INTEGER DEFAULT 0,
            src_pkts INTEGER DEFAULT 0, dst_pkts INTEGER DEFAULT 0,
            is_anomaly INTEGER DEFAULT 0, model_used TEXT DEFAULT 'omni', confidence REAL);
        CREATE TABLE IF NOT EXISTS Alert_Logs (
            id TEXT PRIMARY KEY, timestamp TIMESTAMP NOT NULL, source_ip TEXT NOT NULL,
            target_ip TEXT NOT NULL, dest_ip TEXT NOT NULL, attack_type TEXT NOT NULL,
            confidence REAL NOT NULL, threat_level TEXT NOT NULL, status TEXT NOT NULL,
            model_type TEXT DEFAULT 'omni', execution_mode TEXT DEFAULT 'hybrid',
            shap_values TEXT, lime_values TEXT, raw_payload TEXT);
        CREATE TABLE IF NOT EXISTS App_Settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS Monitored_Devices (
            mac TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS Whitelisted_Destinations (
            ip TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS Whitelisted_Domains (
            domain TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS Whitelisted_Device_Ports (
            mac TEXT NOT NULL,
            port INTEGER NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (mac, port));
        ''')
        additions = {
            'Network_Flows': {
                'device_name': 'TEXT', 'device_mac': 'TEXT', 'src_port': 'INTEGER',
                'dst_port': 'INTEGER', 'prediction': 'INTEGER', 'p_rf': 'REAL',
                'p_cnn': 'REAL', 'execution_mode': 'TEXT',
                'data_source': "TEXT NOT NULL DEFAULT 'unknown'", 'inference_error': 'TEXT',
                'sni': 'TEXT'},
            'Alert_Logs': {
                'data_source': "TEXT NOT NULL DEFAULT 'unknown'", 'sensor_id': 'TEXT',
                'device_name': 'TEXT', 'device_mac': 'TEXT', 'flow_id': 'INTEGER',
                'explanation_meta': 'TEXT', 'attack_type_source': 'TEXT'},
        }
        for table, fields in additions.items():
            present = {r['name'] for r in conn.execute(f'PRAGMA table_info({table})')}
            for column, definition in fields.items():
                if column not in present:
                    conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
        conn.executescript('''
        CREATE INDEX IF NOT EXISTS idx_flows_device ON Network_Flows(device_mac, id);
        CREATE INDEX IF NOT EXISTS idx_flows_origin ON Network_Flows(data_source, id);
        CREATE INDEX IF NOT EXISTS idx_alert_origin ON Alert_Logs(data_source);
        ''')


def insert_network_flow(src_ip, dst_ip, proto='TCP', duration=0, src_bytes=0,
                        dst_bytes=0, src_pkts=0, dst_pkts=0, is_anomaly=0,
                        model_used='omni', confidence=None, sensor_id='rpi3b-edge-01', **metadata):
    row = dict(timestamp=utc_now(), sensor_id=sensor_id, src_ip=src_ip, dst_ip=dst_ip,
               proto=proto, duration=duration, src_bytes=src_bytes, dst_bytes=dst_bytes,
               src_pkts=src_pkts, dst_pkts=dst_pkts, is_anomaly=is_anomaly,
               model_used=model_used, confidence=confidence)
    for key in ('device_name', 'device_mac', 'src_port', 'dst_port', 'prediction', 'p_rf',
                'p_cnn', 'execution_mode', 'data_source', 'inference_error', 'sni'):
        row[key] = metadata.get(key, 'unknown' if key == 'data_source' else None)
    if row['device_mac']:
        row['device_mac'] = str(row['device_mac']).lower()
    with closing(get_db_connection()) as conn, conn:
        cursor = conn.execute(
            f"INSERT INTO Network_Flows ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",
            tuple(row.values()))
        return cursor.lastrowid


def insert_alert(threat):
    keys = ('id', 'timestamp', 'source_ip', 'target_ip', 'dest_ip', 'attack_type',
            'confidence', 'threat_level', 'status', 'model_type', 'execution_mode',
            'data_source', 'sensor_id', 'device_name', 'device_mac', 'flow_id', 'attack_type_source')
    row = {key: threat.get(key) for key in keys}
    row['data_source'] = threat.get('data_source', 'unknown')
    for key, default in (('shap_values', []), ('lime_values', []),
                         ('explanation_meta', {}), ('raw_payload', {})):
        row[key] = json.dumps(threat.get(key, default), allow_nan=False)
    with closing(get_db_connection()) as conn, conn:
        conn.execute(f"INSERT INTO Alert_Logs ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",
                     tuple(row.values()))


def decode_json(value, default):
    try:
        return json.loads(value) if value else default
    except (ValueError, TypeError):
        return default


def get_all_alerts(limit=100, source=None):
    # Saved order stays correct when legacy local timestamps coexist with new UTC timestamps.
    where, params = ('WHERE data_source=?', [source]) if source else ('', [])
    with closing(get_db_connection()) as conn, conn:
        rows = conn.execute(
            f'SELECT * FROM Alert_Logs {where} ORDER BY rowid DESC LIMIT ?',
            [*params, limit]).fetchall()
    result = []
    for raw in rows:
        row = dict(raw)
        for key, default in (('shap_values', []), ('lime_values', []), ('explanation_meta', {})):
            row[key] = decode_json(row.get(key), default)
        row.pop('raw_payload', None)
        result.append(row)
    return result


def get_recent_flows(limit=100, source='live_hardware'):
    where, params = ('WHERE data_source=?', [source]) if source else ('', [])
    with closing(get_db_connection()) as conn, conn:
        return [dict(row) for row in conn.execute(
            f'SELECT * FROM Network_Flows {where} ORDER BY id DESC LIMIT ?', [*params, limit])]


def get_monitored_devices():
    """Return the dashboard-managed list of monitored device MACs."""
    with closing(get_db_connection()) as conn, conn:
        rows = conn.execute(
            'SELECT mac, name, added_at FROM Monitored_Devices ORDER BY added_at').fetchall()
        return [dict(row) for row in rows]


def add_monitored_device(mac: str, name: str):
    """Add or update a monitored device. MAC is normalized to lowercase."""
    mac = mac.strip().lower()
    name = name.strip()
    if not mac or not name:
        raise ValueError("MAC and name are required")
    # Basic MAC validation: six hex octets
    parts = mac.split(":")
    if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        raise ValueError(f"Invalid MAC address format: {mac}")
    with closing(get_db_connection()) as conn, conn:
        conn.execute(
            'INSERT INTO Monitored_Devices (mac, name) VALUES (?, ?) '
            'ON CONFLICT(mac) DO UPDATE SET name=excluded.name',
            (mac, name))


def remove_monitored_device(mac: str) -> bool:
    """Remove a monitored device. Returns True if a row was deleted."""
    mac = mac.strip().lower()
    with closing(get_db_connection()) as conn, conn:
        cur = conn.execute('DELETE FROM Monitored_Devices WHERE mac = ?', (mac,))
        return cur.rowcount > 0


def get_device_summaries():
    # A Pi heartbeat does not prove that each observed IoT device is online.
    with closing(get_db_connection()) as conn, conn:
        rows = conn.execute('''
            SELECT f.*, s.flow_count, s.packet_count FROM Network_Flows f
            JOIN (SELECT device_mac, MAX(id) latest_id, COUNT(*) flow_count,
                  SUM(src_pkts + dst_pkts) packet_count FROM Network_Flows
                  WHERE data_source='live_hardware' AND device_mac IS NOT NULL AND device_mac!=''
                  GROUP BY device_mac) s ON f.id=s.latest_id
            ORDER BY f.device_name, f.device_mac
        ''').fetchall()
    return [dict(device_name=r['device_name'], device_mac=r['device_mac'], sensor_id=r['sensor_id'],
                 last_ip=r['src_ip'], last_seen=r['timestamp'], flow_count=r['flow_count'],
                 packet_count=r['packet_count']) for r in rows]


def get_alert_counts():
    counts = {'live_hardware': 0, 'simulation': 0, 'unknown': 0}
    with closing(get_db_connection()) as conn, conn:
        for row in conn.execute('SELECT data_source, COUNT(*) n FROM Alert_Logs GROUP BY data_source'):
            key = row['data_source'] if row['data_source'] in counts else 'unknown'
            counts[key] += row['n']
    return counts


def clear_all_alerts(source=None):
    with closing(get_db_connection()) as conn, conn:
        if source:
            conn.execute('DELETE FROM Alert_Logs WHERE data_source=?', (source,))
        else:
            conn.execute('DELETE FROM Alert_Logs')


def load_settings(defaults):
    result = dict(defaults)
    with closing(get_db_connection()) as conn, conn:
        for row in conn.execute('SELECT key, value FROM App_Settings'):
            if row['key'] in result:
                result[row['key']] = decode_json(row['value'], result[row['key']])
    return result


def save_settings(settings):
    with closing(get_db_connection()) as conn, conn:
        conn.executemany('INSERT OR REPLACE INTO App_Settings(key,value) VALUES (?,?)',
                         [(key, json.dumps(value, allow_nan=False)) for key, value in settings.items()])


def get_database_stats():
    with closing(get_db_connection()) as conn, conn:
        flows = conn.execute('SELECT COUNT(*) FROM Network_Flows').fetchone()[0]
        alerts = conn.execute('SELECT COUNT(*) FROM Alert_Logs').fetchone()[0]
        breakdown = dict(conn.execute('SELECT attack_type, COUNT(*) FROM Alert_Logs GROUP BY attack_type'))
    return dict(db_size_kb=round(os.path.getsize(DB_PATH)/1024, 2), total_flows_logged=flows,
                total_alerts_logged=alerts, attack_breakdown=breakdown, alert_counts=get_alert_counts())


# ── Whitelisted destination IPs (suppress false-positive alerts) ──────────


def get_whitelisted_destinations():
    """Return the dashboard-managed list of whitelisted destination IPs."""
    with closing(get_db_connection()) as conn, conn:
        rows = conn.execute(
            'SELECT ip, label, reason, added_at FROM Whitelisted_Destinations ORDER BY added_at'
        ).fetchall()
        return [dict(row) for row in rows]


def add_whitelisted_destination(ip: str, label: str, reason: str = ''):
    """Whitelist a destination IP. Alerts to this IP will be suppressed."""
    ip = ip.strip()
    label = label.strip()
    reason = reason.strip()
    if not ip or not label:
        raise ValueError("IP and label are required")
    with closing(get_db_connection()) as conn, conn:
        conn.execute(
            'INSERT INTO Whitelisted_Destinations (ip, label, reason) VALUES (?, ?, ?) '
            'ON CONFLICT(ip) DO UPDATE SET label=excluded.label, reason=excluded.reason',
            (ip, label, reason))


def remove_whitelisted_destination(ip: str) -> bool:
    """Remove a whitelisted destination. Returns True if a row was deleted."""
    ip = ip.strip()
    with closing(get_db_connection()) as conn, conn:
        cur = conn.execute('DELETE FROM Whitelisted_Destinations WHERE ip = ?', (ip,))
        return cur.rowcount > 0


def is_destination_whitelisted(ip: str) -> bool:
    """Fast check whether a destination IP is in the whitelist."""
    with closing(get_db_connection()) as conn, conn:
        row = conn.execute(
            'SELECT 1 FROM Whitelisted_Destinations WHERE ip = ?', (ip.strip(),)
        ).fetchone()
        return row is not None


# ── Whitelisted domains (SNI-based false-positive suppression) ────────────


def get_whitelisted_domains():
    """Return the dashboard-managed list of whitelisted domains."""
    with closing(get_db_connection()) as conn, conn:
        rows = conn.execute(
            'SELECT domain, label, reason, added_at FROM Whitelisted_Domains ORDER BY added_at'
        ).fetchall()
        return [dict(row) for row in rows]


def add_whitelisted_domain(domain: str, label: str, reason: str = ''):
    """Whitelist a domain. Alerts for flows with matching SNI will be suppressed."""
    domain = domain.strip().lower()
    label = label.strip()
    reason = reason.strip()
    if not domain or not label:
        raise ValueError("Domain and label are required")
    with closing(get_db_connection()) as conn, conn:
        conn.execute(
            'INSERT INTO Whitelisted_Domains (domain, label, reason) VALUES (?, ?, ?) '
            'ON CONFLICT(domain) DO UPDATE SET label=excluded.label, reason=excluded.reason',
            (domain, label, reason))


def remove_whitelisted_domain(domain: str) -> bool:
    """Remove a whitelisted domain. Returns True if a row was deleted."""
    with closing(get_db_connection()) as conn, conn:
        cur = conn.execute('DELETE FROM Whitelisted_Domains WHERE domain = ?',
                           (domain.strip().lower(),))
        return cur.rowcount > 0


def is_domain_whitelisted(sni: str) -> bool:
    """Check whether an SNI matches the domain whitelist (exact or wildcard)."""
    if not sni:
        return False
    sni = sni.strip().lower()
    with closing(get_db_connection()) as conn, conn:
        domains = [r[0] for r in conn.execute('SELECT domain FROM Whitelisted_Domains').fetchall()]
    for d in domains:
        if sni == d or (d.startswith('*.') and sni.endswith(d[2:])):
            return True
    return False


# ── Whitelisted device ports (MAC + Port false-positive suppression) ──────


def get_whitelisted_device_ports():
    """Return list of whitelisted MAC + port combinations."""
    with closing(get_db_connection()) as conn, conn:
        rows = conn.execute(
            'SELECT mac, port, reason, added_at FROM Whitelisted_Device_Ports ORDER BY added_at'
        ).fetchall()
        return [dict(row) for row in rows]


def add_whitelisted_device_port(mac: str, port: int, reason: str = ''):
    """Whitelist a specific port for a specific MAC address."""
    mac = mac.strip().lower()
    reason = reason.strip()
    if not mac or not isinstance(port, int):
        raise ValueError("MAC and port are required")
    with closing(get_db_connection()) as conn, conn:
        conn.execute(
            'INSERT INTO Whitelisted_Device_Ports (mac, port, reason) VALUES (?, ?, ?) '
            'ON CONFLICT(mac, port) DO UPDATE SET reason=excluded.reason',
            (mac, port, reason))


def remove_whitelisted_device_port(mac: str, port: int) -> bool:
    """Remove a whitelisted MAC+port combination."""
    with closing(get_db_connection()) as conn, conn:
        cur = conn.execute('DELETE FROM Whitelisted_Device_Ports WHERE mac = ? AND port = ?',
                           (mac.strip().lower(), int(port)))
        return cur.rowcount > 0


def is_device_port_whitelisted(mac: str, port: int) -> bool:
    """Fast check whether a MAC+port combination is in the whitelist."""
    if not mac or port is None:
        return False
    with closing(get_db_connection()) as conn, conn:
        row = conn.execute(
            'SELECT 1 FROM Whitelisted_Device_Ports WHERE mac = ? AND port = ?',
            (mac.strip().lower(), int(port))
        ).fetchone()
        return row is not None

