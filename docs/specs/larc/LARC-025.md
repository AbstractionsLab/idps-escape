---
active: true
derived: false
level: 2.9
links:
- HARC-014: RXkcsJfH9zSPUQ5b1GZ_tcRQ7PRGe6A6TxCOFXi3UJk=
- SRS-051: L_FEEgh5sx0eJ_B6mZtm3kp_90KxFJLwar48ZeSHzbk=
- SRS-055: ysWB5SJEBNrXmKQYG-xHmAiWmgdyjAcTkOqrg1qRW4g=
normative: true
ref: ''
release: Alpha
reviewed: I_Tm3sJlvpRqkfy9UVhQG7vQLKppf0wWc7c9xO-uhyk=
version: '0.1'
---

# RADAR helper enrichment pipeline

The diagram below depicts the real-time log enrichment pipeline implemented by the RADAR Helper service running on Wazuh agents.

## Pipeline overview

The RADAR Helper is a multi-threaded Python daemon that monitors authentication logs, enriches them with geographic and behavioral context, and writes enhanced logs for Wazuh to ingest. This enrichment enables signature-based detection of geographic anomalies and impossible travel scenarios.

## Pipeline stages

### 1. Log monitoring
**AuthLogWatcher** continuously monitors `/var/log/auth.log`:

- Implements tail-like following with rotation handling
- Detects SSH authentication events (success and failure)
- Extracts: username, source IP, timestamp (parsed from the log line via `parse_event_ts()`), outcome

> **Note**: The timestamp used for all subsequent behavioral calculations is parsed directly from the log line header, not taken from time at processing. This ensures accurate velocity estimates for replayed or delayed log streams.

### 2. Geographic enrichment
**GeoLookup Service** queries MaxMind GeoLite2 databases:

- City database: `/usr/share/GeoIP/GeoLite2-City.mmdb`
- ASN database: `/usr/share/GeoIP/GeoLite2-ASN.mmdb`

Extracted fields:

- `country`: ISO 3166-1 alpha-2 country code
- `region`: State/province name
- `city`: City name
- `asn`: Autonomous System Number
- `asn_placeholder_flag`: True if ASN lookup failed
- Geographic coordinates: latitude, longitude (for velocity calculation)

### 3. User state management
**UserState** maintains per-user historical data:

- Last login location (latitude, longitude)
- Last login timestamp (epoch seconds, sourced from the parsed event timestamp)
- ASN history (90-day sliding window)

State enables temporal and behavioral analysis:

- Velocity between consecutive logins
- ASN novelty detection
- Country change tracking

### 4. Behavioral calculations

**Geographic velocity**:
```
Algorithm: Calculate velocity between consecutive logins
  Input: previous_location (lat, lon, event_timestamp),
         current_location  (lat, lon, event_timestamp)

  distance_km ← haversine_distance(prev_lat, prev_lon, curr_lat, curr_lon)
  dt_h        ← abs(curr_event_ts - prev_event_ts) / 3600
  if abs(dt_h) < DT_EPS_H (1e-9):
      dt_h ← DT_EPS_H          // guard against near-simultaneous events
  velocity_kmh ← distance_km / dt_h

  Output: velocity_kmh
```

> **Note**: Velocity is no longer capped at a fixed maximum. The previous 2000 km/h ceiling has been removed. The `DT_EPS_H` guard (1×10⁻⁹ hours) prevents division by zero for events with identical or near-identical timestamps without distorting physically plausible velocities.

**Country change indicator**:
```
Algorithm: Detect country transition
  country_change_i ← (curr_country ≠ prev_country) ? 1 : 0
```

**ASN novelty indicator**:
```
Algorithm: Check if ASN is novel within retention window
  asn_novelty_i ← (curr_asn ∉ user_asn_history[−90d]) ? 1 : 0
```

### 5. Enriched log writing
Formatted log line written to `/var/log/suspicious_login.log`:
```
timestamp hostname sshd[PID]: radar_outcome="success" radar_user="alice"
  radar_src_ip="203.0.113.42" radar_country="US" radar_region="California"
  radar_city="San Francisco" radar_asn="15169" radar_asn_placeholder_flag="false"
  radar_geo_velocity_kmh="450.23" radar_country_change_i="1"
  radar_asn_novelty_i="0"
```

### 6. Wazuh ingestion
Wazuh agent monitors `/var/log/suspicious_login.log`:

- Custom decoders extract radar_* fields
- Rules evaluate conditions (velocity > 900 km/h, country not in whitelist)
- Active responses trigger on rule matches

## Algorithms

**Haversine distance** (great-circle distance):
```
Algorithm: Calculate great-circle distance between two geographic points
  Input: lat1, lon1, lat2, lon2 (in degrees)

  R    ← 6371.0088  // Earth mean radius in km
  Δlat ← radians(lat2 - lat1)
  Δlon ← radians(lon2 - lon1)

  a ← sin²(Δlat/2) + cos(radians(lat1)) × cos(radians(lat2)) × sin²(Δlon/2)
  c ← 2 × atan2(√a, √(1-a))
  distance ← R × c

  Output: distance (in kilometers)
```

**ASN history maintenance**:
```
Algorithm: Maintain time-windowed ASN history for user
  Input: user_state, retention_window_sec (default: 90 × 24 × 3600 = 7,776,000 s)

  cutoff_timestamp ← current_event_ts - retention_window_sec

  for each (asn, timestamp) in user_state.asn_history:
    if timestamp < cutoff_timestamp:
      remove (asn, timestamp) from user_state.asn_history
      if asn not referenced by any remaining entry:
        remove asn from user_state.asn_set

  Output: updated user_state with pruned history and set
```

**Timestamp parsing** (`parse_event_ts`):
```
Algorithm: Parse log line timestamp to Unix epoch float
  Input: ts_str (string)

  if ts_str matches ISO 8601 pattern (contains "T" and timezone offset):
    return datetime.fromisoformat(ts_str).timestamp()

  if ts_str matches syslog pattern (e.g., "Jan 15 10:30:00"):
    reconstruct datetime using current year and local timezone
    return datetime(...).timestamp()

  fallback:
    return time.time()

  Output: float (Unix epoch seconds)
```

## Multi-threading design

- **Main thread**: Creates a `RadarLogger` singleton (`RADAR_LOG`) at startup, instantiates `AuthLogWatcher` with it, and manages the watcher lifecycle
- **RadarLogger**: Encapsulates all logger setup; provides a shared debug logger and a factory method (`build_out_logger`) for per-watcher output loggers
- **Watcher threads**: One per log file; `AuthLogWatcher` is active in production; `AuditLogWatcher` is defined as a stub for future use
- **Graceful shutdown**: Stop event signaling and thread join with 5-second timeout on exit

## Implementation reference

See [radar/radar-helper/radar-helper.py](../../../radar/radar-helper/radar-helper.py) for complete implementation.

## See also

- `/docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md` for usage in GeoIP scenario
- `/docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md` for usage in suspicious login scenario