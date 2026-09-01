# RADAR GUI — user manual

The RADAR GUI is a browser-based control panel covering the whole RADAR
lifecycle: configuring external services, tuning detection and response, and
deploying scenarios to your Wazuh manager. Anything you can do from the GUI you
can also do from the CLI — see [Operations](./radar-operations.md) — but the GUI
is the recommended interface.

Start it with:

```bash
./radar.sh gui
```

Then open `http://localhost:5000`.

![RADAR GUI walkthrough](/docs/manual/_figures/RADAR_GUI.gif)

The left sidebar has three pages:

| Page | Use it to |
|------|-----------|
| **RADAR Scenarios** | Tune risk weights, tier thresholds, and mitigations per scenario |
| **Connectors** | Set and test URLs and credentials for every external service |
| **Deployment** | Deploy scenarios, onboard agents, run the detector, check health, tear down |

---

## First-time setup

Work through these in order:

1. **[RADAR Scenarios](#radar-scenarios)** — tune thresholds and decide whether
   to let RADAR execute mitigations automatically.
2. **[Connectors](#connectors)** — fill in OpenSearch, Wazuh API, Dashboards,
   SMTP, and (if you are using `suspicious_login` or `geoip_detection`) MaxMind.
   Hit **Test all** and get everything green.
3. **[Deployment → Scenario Management](#scenario-management)** — deploy your
   first scenario.
4. **[Deployment → Agent Management](#agent-management)** — mint a token and
   onboard an endpoint.
5. **[Deployment → Anomaly Detector](#anomaly-detector)** — for ML scenarios,
   start the detector.
6. **[Deployment → Status](#status)** — confirm everything is healthy.

---

## RADAR Scenarios

![RADAR GUI — RADAR Scenarios page](/docs/website/assets/RADAR_GUI_RADAR_Scenarios.png "RADAR Scenarios page: risk weights, time windows, tier thresholds, mitigations")

A sidebar lists every scenario. Click one to load its configuration into the
right-hand panel. **Save** writes to `ar.yaml` and takes effect immediately.

**Default (baseline)** is pinned at the top of the list. It carries the
fleet-wide PowerShell / command-shell detection rules, and every other scenario
inherits its values as defaults — so changing something there changes it
everywhere it has not been overridden.

Each tab carries badges:

| Badge | Meaning |
|-------|---------|
| `Baseline` | This is the default scenario |
| `Deployed` / `Not deployed` | Whether the scenario is currently applied to the manager |
| `Signature` / `AD` / `Hybrid` | Which detection sources it uses — derived from the weights below |
| `Mitigations ON` | Automatic mitigation execution is enabled for this scenario |

### Risk weights

Three weights decide how the final risk score in `[0, 1]` is composed. **They
must sum to 1.0** — the GUI shows the running total and refuses to save
otherwise.

| Weight | Source |
|--------|--------|
| `w_ad` | Anomaly detector score |
| `w_sig` | Signature rule score |
| `w_cti` | Threat-intelligence lookup score from DECIPHER |

The scenario's type badge follows from these: `w_sig` only → Signature,
`w_ad` only → AD, both → Hybrid.

### Signature scoring

- **`signature_impact`** — how severe a fire of this rule is (0–1).
- **`signature_likelihood`** — estimated true-positive rate for the rule (0–1).


### Anomaly detection scoring

`anomaly_grade` and `confidence` are supplied at runtime by the OpenSearch
detector — the fields here are informational.

### Time windows

How far back RADAR looks when it correlates evidence at alert time.

- **`delta_ad_minutes`** — look-back for anomaly-detector events.
- **`delta_signature_minutes`** — look-back for signature events and the CTI
  lookup.

### Risk tiers and thresholds

Four tiers, T0 to T3. You set the upper boundary of T0, T1, and T2; T3 always
runs to 1.0. Boundaries must be non-decreasing — setting two equal simply leaves
that tier empty, which is a legitimate way to switch a tier off.

| Tier | Default boundary | Response |
|------|-----------------|----------|
| T0 | 0.0 → `tier1_min` | No action — the event is logged only |
| T1 | → 0.33 | Email notification + Flowintel case |
| T2 | → 0.66 | Email + Flowintel case + tier-2 mitigations |
| T3 | → 1.0 | Full response + tier-3 mitigations |

For how to choose these numbers, see [Tuning](./radar-tuning.md).

### Mitigations per tier

T0 and T1 have no executable actions. For T2 and T3, add actions from the
**+ Add action** dropdown; click the `✕` on a tag to remove it.

| Action | Effect |
|--------|--------|
| `firewall-drop` | Blocks the source IP on the affected agent |
| `lock_user_linux` | Locks the Linux account involved in the alert |
| `terminate_service` | Terminates the suspicious process or service |

**Allow automatic mitigation execution** — with this off, RADAR plans and logs
every action but executes none. Check each scenario for `Allow automatic mitigation execution` before you deploy.

### Bound rule IDs

Read-only, at the bottom: the Wazuh rule IDs this scenario ships, split into AD
and signature rules. Useful when you are cross-referencing an alert you saw in
the Wazuh dashboard.

---

## Connectors

![RADAR GUI — Connectors page](/docs/website/assets/RADAR_GUI_Connectors.png "Connectors page: credential fields and per-connector test buttons")

Credentials and URLs for every external service. Values are written to `.env` at
the RADAR root; uploaded CA certificates go to `.certs/`.

**Test all** (top right) runs every connectivity check in sequence. Each card
also has its own **Test** and **Save**. The dot in each card header is grey
(not tested this session), green (last test passed), or red (last test failed).
Password fields that already hold a value get a **Show** button.

| Connector | Fields | Test button |
|-----------|--------|-------------|
| **OpenSearch / Wazuh Indexer** | URL, User, Password, SSL verification (+ CA upload) | Test connection |
| **Wazuh API** | API URL, Manager address, Auth user, Auth password | Test connection |
| **OpenSearch Dashboards** | URL, User, Password, SSL verification (+ CA upload) | Test connection |
| **SMTP / Email** | SMTP host, Port, User, Password, Recipient, STARTTLS | Send test email |
| **DECIPHER** | Base URL, SSL verification (+ CA upload), Timeout (s) | Test connection |
| **MaxMind GeoLite2** | License key | Validate key |
| **Webhook** | Webhook name, Webhook URL | Send ping |

Notes worth knowing:

- **Manager address** on the Wazuh API card is the address agents and the AR
  pipeline use to reach the manager — not necessarily the same host you are
  browsing from.
- **Send test email** performs an SMTP login; it does not deliver a message.
- **MaxMind** is required by `suspicious_login` and `geoip_detection`, which use
  GeoLite2-City and GeoLite2-ASN for manager-side enrichment. A free key from
  [MaxMind](https://www.maxmind.com/en/geolite2/signup) is enough. Without it,
  those two scenarios will deploy but not enrich.
- **Send ping** POSTs `{"ping": true}` to the webhook URL to confirm it is
  reachable.

---

## Deployment

![RADAR GUI — Deployment page](/docs/website/assets/RADAR_GUI_Deployment.png "Deployment page: six tabs with a live output stream")

Six tabs across the top; two of them have their own sub-tabs. An **Output**
panel below streams command output line by line, with **Clear** and **Copy**.
Long-running actions show a **Stop streaming** button.

Several actions need `sudo` on the machine running the GUI. RADAR prompts for it
the first time it is needed, keeps it in memory for the browser session only,
and never writes it to disk. Restarting the Flask server clears it.

### Scenario Management

![RADAR GUI — Scenario Management tab](/docs/website/assets/RADAR_GUI_Scenario_Management.png "Scenario Management tab: deployment and undeployment")

**Deploy scenario.** Runs `build-radar.sh`.

| Field | Notes |
|-------|-------|
| Plain Wazuh only | Brings up manager/indexer/dashboard with no RADAR scenario (`--core-only`). Disables the scenario dropdown |
| Scenario | The manager always runs locally |

`sudo` is required unconditionally — applying a scenario's configuration to the
manager needs it even when the stack is already up. Buttons: **Preview
command**, **Deploy**, **Stop streaming**.

**Undeploy scenario.** Reverses a scenario's manager-side deployment: empties
its group's `agent.conf`, unenrolls its agents from that group, removes its
`ossec.conf` active-response block, and removes any decoder, rule, or list file
it shipped once no other deployed scenario still needs it.

It deliberately leaves the always-shared pieces alone — the baseline `default`
and `shared auth_log_enrichment` blocks, and the enrichment and active-response
scripts on the manager filesystem. Safe to re-run.

### Anomaly Detector

![RADAR GUI — Anomaly Detector tab](/docs/website/assets/RADAR_GUI_Anomaly_Detector.png "Anomaly Detector tab: creating the detector")

Runs `run-radar.sh`. Only Hybrid and AD scenarios appear here — Signature
scenarios do not use an OpenSearch detector.

| Field | Notes |
|-------|-------|
| Scenario | Hybrid and AD only |
| Ingest training dataset | Populates the indexer with synthetic baseline data. Required the first time a scenario has no real traffic — without documents in the index, detector creation fails |

There is no undo here: `ingest training dataset` writes into the OpenSearch indexer rather than a
config file. To remove Anomaly Detector and data from a run, delete them manually from the Wazuh
dashboard.

### Agent Management

![RADAR GUI — Agent Management tab](/docs/website/assets/RADAR_GUI_Agent_Management.png "Agent Management tab: onboarding and deregistering the agent")

**Onboard agent.** Mints a short-lived enrollment token, prints a ready-to-run
`bootstrap-agent.sh` command, and opens the port-1515 enrollment window for the
same duration.

| Field | Notes |
|-------|-------|
| Scenario | Token is minted for `default` plus this scenario's group. `suspicious_login` and `geoip_detection` also get `radar_shared` |
| Token expiry (minutes) | Default 60 |
| Manager address (optional) | Auto-detected if blank |

When minting finishes, the bootstrap command appears in a highlighted box with a
**Copy command** button — it is pulled out of the log stream deliberately,
because it starts with `sudo` and is easy to scroll past. Run it under `sudo` on
the target endpoint.

**Deregister agent.** Removes an agent from the manager entirely, freeing its
name and IP for a fresh enrollment.

| Field | Notes |
|-------|-------|
| Agent name | Required; must match exactly |
| Agent IP | Optional, used if the name does not resolve |
| Keep the entry reserved | Unchecked (default) frees the name/IP immediately. Checked keeps it reserved, so re-onboarding the same endpoint needs a different name or IP |

If the Wazuh agent service is still running on the endpoint, it will try to
re-enroll on its own — stop it there first if that is not what you want.

**Enrollment window.** Port 1515 is closed by default via a host firewall rule.
Minting a token opens it automatically; use this sub-tab to open, close, or
check it independently — for example, to onboard several endpoints in one window.

| Field | Notes |
|-------|-------|
| Minutes | Default 30. The window closes automatically when it elapses |

Buttons: **Check status**, **Open**, **Close**.

### Group Management

![RADAR GUI — Group Management tab](/docs/website/assets/RADAR_GUI_Group_Management.png "Group Management tab: enroll and unenroll")

Assigns or unassigns an already-enrolled agent's scenario groups from the
manager side — no SSH to the endpoint needed. Use this when an agent was already
enrolled before you ran `bootstrap-agent.sh` against it, since group assignment
at enrollment time only applies to genuinely new agents.

| Field | Notes |
|-------|-------|
| Agent IP | Preferred — resolution is tried by IP first |
| Scenario | Determines which groups are assigned or removed |
| Agent name | Fallback if the IP does not resolve |

**Unenroll from groups** removes only the scenario's own group. `default` and
`radar_shared` are left in place, since another scenario may still need them.

> **`log_volume` is a special case.** Assigning an agent here delivers the
> group's config but does *not* install the systemd timer that produces the
> metric — only `bootstrap-agent.sh` does that, at bootstrap time. The agent will
> be told to watch `/var/log/radar/log_volume_metric.log` but nothing will write
> to it. Re-run `bootstrap-agent.sh --group log_volume` on that endpoint.

### Status

![RADAR GUI — Status tab](/docs/website/assets/RADAR_GUI_Status.png "Status tab: health check")

Runs `health-radar.sh`.

| Field | Notes |
|-------|-------|
| Scenario filter | **all** or a specific scenario |
| Agent names | Optional, comma-separated — adds agent connectivity and group-membership checks |

Every line is marked `OK`, `WARN`, or `FAIL`. The check is read-only; it never
changes anything.

### Teardown

![RADAR GUI — Teardown tab](/docs/website/assets/RADAR_GUI_Teardown.png "Teardown tab: bringing down the stack")

Stops and removes the manager, indexer, dashboard, and webhook containers.

| Field | Notes |
|-------|-------|
| Delete all data | Unchecked: containers stop, data stays on disk for next time. Checked: indices, dashboards, enrollment state, and certificates are permanently deleted |

A confirmation checkbox must be ticked before the **Tear down** button enables.
Needs `sudo`.

---

## Troubleshooting

See [Troubleshooting](./radar-troubleshooting.md) for connector failures, agents
that will not enroll, and scenarios that do not appear in a dropdown.