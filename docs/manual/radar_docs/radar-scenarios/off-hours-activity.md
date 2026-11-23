# Off-hours activity

Part of the [suspicious login](./suspicious_login_explained.md) scenario. Implements [SRS-062](../../../specs/srs/SRS-062.md).

You declare each user's working hours in `radar/config.yaml`. RADAR marks every archived event of a listed user as on or off hours, and one of two consumers turns off-hours events into alerts:

| Mode | For | How it decides | Wazuh rule |
|---|---|---|---|
| `rule` | Staff whose normal number of off-hours events is zero | Reports the start of every off-hours burst. Needs no training and works from the first event. | 210041 |
| `model` | Administrators and on-call staff who sometimes work late | A per-user anomaly detector learns each user's usual number of off-hours events per interval and reports an unusual count | 210040 |

Both alerts enter the same path as other RADAR anomaly alerts: webhook, `/var/log/ad_alerts.log`, the `opensearch_ad` decoder, then `radar_ar.py`, which scores them as the scenario's anomaly side and fuses them with the user's signature alerts (see [Off-hour anomalies and fusion](./suspicious_login_explained.md#off-hour-anomalies-and-fusion)).

## How events are marked

An ingest pipeline, `radar-off-hours`, adds three fields to each archived event whose user is listed (or, with `default_group`, to any user's event):

| Field | Value |
|---|---|
| `radar.user` | The user name in lower case, from the first non-empty field in `user_fields` |
| `radar.schedule_group` | The user's schedule group |
| `radar.off_hours` | `1` outside the group's working hours, otherwise `0` |

An event whose time can't be read gets `radar.off_hours_error` instead, and is still indexed. Events of users who aren't listed, and of users in `ignore_users`, are left unchanged.

The pipeline runs in two places:

- **Events from Filebeat (real agents).** The Wazuh archives pipeline calls it as a step (tag `radar_off_hours`, from `radar/scenarios/pipelines/suspicious_login/radar-off-hours-step.json`). `sudo ./radar.sh build suspicious_login` (`build-radar.sh`, through `radar_deploy/manager-apply-scenario.sh`) adds it to the manager's archives `pipeline.json`, the host file that `volumes.yml` mounts at `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` (by default `/srv/wazuh/manager/filebeat/pipeline-archives.json`), and restarts the manager. `run-radar.sh` does not add it. The step has `ignore_failure`, so if the pipeline is missing, events are only left unmarked and none are lost.
- **Events RADAR writes itself.** The synthetic ingest and the backfill name the pipeline in the request (`?pipeline=radar-off-hours`).

## The schedule block

Under `scenarios.suspicious_login.off_hours`:

```yaml
off_hours:
  enabled: true
  backfill_days: 45                 # history the backfill marks; model mode trains on it
  user_fields: [data.user, data.srcuser, data.dstuser]
  # default_group: office           # unset: users not listed are not evaluated
  ignore_users: [root]              # never evaluated, even with a default group
  groups:
    office:
      timezone: Europe/Luxembourg   # IANA name; summer time is handled
      workdays: [1, 2, 3, 4, 5]     # ISO weekdays on which a shift starts (1 = Monday)
      start: "08:00"                # quoted: YAML reads 08:00 unquoted as a number
      end: "19:00"                  # exclusive; "24:00" is allowed
      mode: rule
    night_shift:
      timezone: UTC
      workdays: [1, 2, 3, 4, 5]
      start: "22:00"                # start > end crosses midnight; the hours after midnight
      end: "06:00"                  # belong to the shift that started the day before
      mode: rule
    admins:
      timezone: Europe/Luxembourg
      workdays: [1, 2, 3, 4, 5]
      start: "08:00"
      end: "19:00"
      mode: model
  users:
    alice: office
    bob: night_shift
    trent: admins
  event_filter:                     # optional: count only some event types (empty values = all)
    field: decoder.name
    values: []
  rule_mode:
    interval_minutes: 5
    delay_minutes: 1
    quiet_minutes: 30
    min_events: 1
    anomaly_grade: 1.0
    anomaly_confidence: 1.0
  model_mode:
    interval_minutes: 30
    window_delay_minutes: 10
    shingle_size: 1
    anomaly_grade_threshold: 0.01
    confidence_threshold: 0.01
    min_events: 1
    max_entities: 10
```

User names are matched in lower case. sudo events name the actor in `data.srcuser` and the target (often `root`) in `data.dstuser`; sshd logins name the user in `data.dstuser`. Keep `data.srcuser` before `data.dstuser` so that a sudo event counts for the person who ran it.

`off_hours.py validate` reports every problem in the block at once. It rejects, among others: unknown time zones, unquoted or impossible times, equal start and end, weekdays outside 1–7, unknown modes or groups, a user listed twice or also in `ignore_users`, and unknown keys (for example a leftover `lookback_minutes`).

### Rule mode settings

Every `interval_minutes`, the monitor counts each user's off-hours events in the current window, which is the last interval ending `delay_minutes` ago, and in the `quiet_minutes` before it. A user is reported when they have at least `min_events` in the window and none in the quiet period. So a long session or a burst is reported once, and off-hours activity is reported again only after `quiet_minutes` without any. `delay_minutes` leaves time for events that are indexed late. The windows of consecutive runs abut, so every event is counted exactly once.

The alert carries a fixed `anomaly_grade` and `anomaly_confidence` (a declared schedule is either broken or not), the number of events (`off_hours_count`), the first and last event time, and the schedule group.

### Model mode settings

The detector `SUSPICIOUS_LOGIN_OFF_HOURS_DETECTOR` has one feature, `sum(radar.off_hours)` per interval and user (category field `radar.user`), over the events of model-mode groups only. On-shift intervals give 0, so the baseline is each user's usual off-hours count. Intervals without any event are skipped rather than scored as 0. Its results go to `opensearch-ad-plugin-result-suspicious-login-off-hours`.

Its monitor `SuspiciousLogin-OffHours-ModelMode-Monitor` reports anomalies at or above both thresholds. It reports an anomaly only when the user had at least `min_events` off-hours events in that interval, so a drop in off-hours work is never reported. The trigger keeps the name `SuspiciousLogin-OffHour-Detected`, which rule 210040 matches.

## Adding a user or a group

1. Edit the block: add the user under `users`, or add a group under `groups` and assign users to it.
2. Check it: `docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" radar-cli:latest python off_hours.py validate` (from `radar/`).
3. Redeploy: `./radar.sh run suspicious_login` (or the GUI). The command replaces the pipeline and updates the monitors and the detector. A changed detector is stopped, updated and started again. The Filebeat step only needs adding once, by `sudo ./radar.sh build suspicious_login`.
4. To mark the user's past events, which model mode needs before it can learn, run the backfill (next section).

The pipeline only marks events indexed after it changed, or events passed through the backfill. Events marked under an earlier schedule keep their old flag.

## Commands

`radar/run-radar.sh suspicious_login` runs `deploy`, the synthetic ingest (with `--ingest true`), `backfill` and `monitors`, in this order. To run any of the commands below on its own, use the `radar-cli` image from `radar/`. The function passes the connection settings from your shell, so first export `OS_URL`, `OS_USER`, `OS_PASS` and `OS_VERIFY_SSL` (and, for `monitors`, `WEBHOOK_URL` and `WEBHOOK_SHARED_SECRET`) with the values from `.env`; `OS_URL` must be the indexer as the container reaches it:

```bash
off_hours() { docker run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" -e OS_URL -e OS_USER -e OS_PASS -e OS_VERIFY_SSL -e WEBHOOK_URL -e WEBHOOK_SHARED_SECRET radar-cli:latest python off_hours.py "$@"; }

off_hours validate          # check the block
off_hours deploy            # pipeline, legacy index template (order 10), mapping on existing archive indices
off_hours backfill          # mark archive events of the last backfill_days days (--days N to override)
off_hours monitors          # rule-mode monitor, model-mode detector and monitor; stops the replaced detectors
off_hours summary --days 1  # events and off-hours events per user
off_hours dry-run           # run the rule-mode monitor now without sending (--mode model for the other)
off_hours status            # each hop of both modes: monitor alerts, webhook lines, Wazuh alerts, detector state
off_hours undeploy          # remove the pipeline and template (flags already written stay)
```

The backfill runs as a background task in OpenSearch and the command waits for it. It touches only events that have a user and no flag yet. Without a `default_group` it touches only the listed users' events.

`monitors` also runs when the block is absent or `enabled: false`, and then removes the off-hours monitors and detector. With no rule-mode group it removes the rule-mode monitor; with no model-mode group, the detector and its monitor.

### Replaced detectors

This design replaces the scenario's earlier time-of-day detector (`SUSPICIOUS_LOGIN_DETECTOR`, monitor `SuspiciousLogin-OffHour-Monitor`) and the unused `off_hour_login` scenario (`OFF_HOUR_LOGIN_DETECTOR`, monitor `OffHourActivity-PerUser-Monitor`). On redeploy, `monitors` stops those detectors and disables their monitors. It does not delete them, so their history stays available. Delete them in **Anomaly Detection** and **Alerting** when you no longer need it.

## Checking it works

- `off_hours summary --days 1` lists, per user, the marked events and the off-hours ones. A user missing from it isn't listed or has no events. Events with `radar.off_hours_error` are counted at the bottom.
- `off_hours status` follows each alert hop by hop:
  - the monitor's alerts, with action errors;
  - the webhook's line as Wazuh archived it, with its decoded fields (`data.off_hours_count` and `data.schedule_group` for rule mode) and the rule it matched;
  - the 210041 and 210040 alerts.
- The checks in `radar/radar-test-framework/checks/` run against a live cluster (each prints PASS or FAIL per step):
  - `off_hours_simulate.py` runs the shared case table (`radar/tests/py/fixtures/off_hours_cases.yaml`) through the real pipeline with `_simulate`.
  - `off_hours_rule_e2e.py` replays rule-mode runs at chosen times on a temporary index and pipeline, then deletes them. It checks: one alert for a user always off hours, none for one always on hours, no second alert during a burst, an alert again after the quiet period, the originally missed event (bob, 2026-09-18 02:05 UTC), and the rendered webhook body.
  - `off_hours_model_history.py` runs the model-mode detector's historical analysis over the synthetic history. It checks that trent's 02:00 burst is flagged and that the rule-mode users are outside the detector. It also reports any anomalies on trent's ordinary evenings.

## Synthetic data

`run-radar.sh suspicious_login --ingest true` writes 45 days of history and 14 days ahead:

- alice, bob and oscar work their shifts in rule-mode groups that have a one-hour margin, so none of their events is off hours;
- trent (model mode, Luxembourg time) works 08:00–19:00 and on about two workday evenings a week adds 1–3 events between 21:00 and midnight;
- one burst of 30 events at about 02:00 local, about a week ago.

The ingest settings are under `scenarios.suspicious_login.ingest.users`.

## Known limits

- Declared schedules need upkeep when people change roles or teams.
- Public holidays, leave and approved overtime aren't modelled, so they produce alerts.
- Events indexed later than `delay_minutes` (rule mode) or `window_delay_minutes` (model mode) after they happened are not evaluated.
- Model mode reports an anomaly whenever the interval has at least `min_events` off-hours events, even if that count is lower than the user's usual one.
- The webhook rejects entity names containing `@`, so such user names (for example e-mail-style logins) produce no alert line.
- Events already marked keep their flag when a schedule changes: only events indexed afterwards follow the new schedule, because the backfill skips events that carry a flag. Model mode therefore needs a few days to relearn a user whose hours changed.
