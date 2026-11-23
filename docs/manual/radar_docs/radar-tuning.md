# Tuning detection and response

Everything here is edited on the **RADAR Scenarios** page of the GUI, or
directly in `scenarios/active_responses/ar.yaml`. Changes reach the manager the
next time the scenario is deployed.

Each scenario's block stands on its own. The `default` scenario is a scenario
like the others: it scores the alerts matched by its own `signature.rule_ids`
and `rule_groups`, which no dedicated scenario covers. Its values are not
inherited. A value missing from a scenario's block falls back to
`radar_ar.py`'s built-in defaults (weights 0, tiers 0 / 0.33 / 0.66,
`allow_mitigation` false), not to `default`. The GUI only *displays*
`default`'s values in fields the scenario leaves unset; they apply to that
scenario once you **Save** it, which writes them into its own block.

---

## How the risk score is built

Every alert gets a score in `[0, 1]` combining up to three sources, weighted:

```
risk  =  w_ad · (anomaly_grade × confidence)
       + w_sig · (signature_impact × signature_likelihood)
       + w_cti · cti_score
```

`w_ad + w_sig + w_cti` must equal 1.0.

### What each alert contributes

Each alert carries one detection term of its own:

- An alert matched by a scenario's `ad.rule_ids` carries the anomaly term. Its
  own signature term is 0.
- An alert matched by `signature.rule_ids` or `rule_groups` carries the
  signature term. Its own anomaly term is 0.
- A scenario counts as *hybrid* in `ar.yaml` only when one rule ID is listed in
  both `ad.rule_ids` and `signature.rule_ids`. No shipped scenario does this.
- The CTI term is non-zero only for scenarios that have a DECIPHER analysis
  endpoint: `suspicious_login` and `scanning_detection`. For every other
  scenario it is always 0, even when DECIPHER is running.

Without [fusion](#combining-signature-and-anomaly-alerts-fusion), a single alert
can therefore never score more than the weight of its own term plus `w_cti`.
Take this into account when you place tier boundaries (see
[Reachable tiers](#reachable-tiers)).

### Combining signature and anomaly alerts (fusion)

A scenario that has both an anomaly detector and signature rules can combine
the two over time. When an alert fires, RADAR looks back for the strongest
alert of the *other* kind on the same entity (a user, or an agent), and uses its
score, discounted by the time between them, for the term the alert cannot carry
itself. The shipped `suspicious_login` scenario has fusion enabled:

```yaml
suspicious_login:
  fusion:
    enabled: true
    window_minutes: 30
    ad_lead_minutes: 10
    key:
      ad: data.entity_keyword
      signature: [data.dstuser, data.srcuser, data.user, data.username]
```

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Fusion is off unless this is `true` |
| `window_minutes` | `30` | How far apart two alerts may be and still combine |
| `ad_lead_minutes` | `0` | How far before the anomaly's data window a signature alert still counts as inside it. A detector reacts to change over its shingle, so use `(shingle_size − 1) × detector_interval` |
| `key.ad` | `data.entity_keyword` | Field of the anomaly alert that names the entity (the detector's `categorical_field` value) |
| `key.signature` | `agent.name` | Field(s) of a signature alert that must equal that entity |

How the time gap is weighted: a signature alert inside the anomaly's data
window (extended back by `ad_lead_minutes`) counts in full. Outside it, its
weight falls linearly to 0 at `window_minutes` from the window. Only the
strongest matching alert counts, never a sum, so a burst of 20 failed logins
does not count 20 times.

What fusion guarantees:

- **Nothing waits.** Each alert is decided as soon as it fires, with whatever
  evidence exists. Whichever alert arrives second gets the combined score.
- **A missing counterpart is not evidence against.** With no match, or if the
  lookup fails, the alert is scored exactly as it would be on its own. Fusion
  can only raise a score.
- **Mitigation targets still come only from the alert being decided.** An
  anomaly alert names no source IP and no Linux user, so a combined decision on
  an anomaly alert notifies and opens a case but blocks or locks nothing. A
  combined decision on a signature alert acts on that alert's own IP and user.
- **Only genuine anomaly alerts count**: those the webhook agent read from
  `/var/log/ad_alerts.log`.

Anomaly alerts arrive late: the detector interval, its delay and the monitor
interval after the data they describe. For `suspicious_login`, off-hours alerts
in rule mode arrive 1 to 11 minutes after the events, and in model mode 40 to 70
minutes after (30-minute interval, 10-minute window delay, 30-minute monitor).
The gap is measured from the anomaly's data window, not from its arrival, so a
late alert still combines with the signature alerts around its data.
In the usual order, a signature alert comes first and is decided on its own,
then the anomaly alert combines with it. Repeated signature alerts in the
window (an ongoing brute force) then combine with the anomaly and can escalate
to the tier that acts.

Fusion applies only when the scenario has both `ad.rule_ids` and signature
`rule_ids` or `rule_groups`, and both `w_ad` and `w_sig` are above 0. RADAR
searches `wazuh-alerts-*`; set `OS_ALERTS_INDEX` in `active_responses.env` if
your alerts live elsewhere. The matched alert (ID, rule, gap, weight) is shown
in the email and the Flowintel case under the scenario details, as `fusion`.
The GUI keeps the `fusion` block when it saves a scenario, but does not edit it.

| Weight | Raise it when | Lower it when |
|--------|---------------|---------------|
| `w_ad` | The detector has a good baseline and you trust it | The model is new or noisy |
| `w_sig` | Your rules are precise and low-noise | Rules fire often on benign activity |
| `w_cti` | DECIPHER is well-fed and its hits are meaningful | DECIPHER is not deployed — set it to 0 |

Typical starting points:

| Scenario type | `w_ad` | `w_sig` | `w_cti` |
|---------------|--------|---------|---------|
| Signature-only | 0.0 | 0.6–0.7 | 0.3–0.4 |
| ML-only | 0.9 | 0.0 | 0.1 |
| Hybrid | 0.3 | 0.4 | 0.3 |

If DECIPHER is not running, or the scenario has no DECIPHER analysis endpoint,
move `w_cti` into the other weights rather than leaving it — a CTI weight with
no CTI source drags every score down.

---

## Signature scoring

- **`signature_impact`** — how bad it is if this rule is right. A rule that
  detects account lockout is not as impactful as one that detects a root shell.
- **`signature_likelihood`** — how often this rule is right. Chatty rules with
  many false positives belong low.

`ar.yaml` also accepts a per-rule form, which is what **every shipped scenario
except the AD-only ones (`log_volume`, `linux_resource_utilization`) uses**:

```yaml
signature_likelihood:
  - rule_id: ["100401", "100402"]
    weight: 0.6
  - rule_id: "23503"
    weight: 0.001
  - rule_group: "authentication_failures"
    weight: 0.3
```

This is how you suppress one noisy rule without dulling the whole scenario.

---

## Time windows

When an alert fires, RADAR fetches the events logged on the same agent shortly
before it. It uses them for the alert email, the DECIPHER request and the
Flowintel case, but **not** for the risk score.

- **`delta_ad_minutes`** — look-back for an anomaly alert. `log_volume` and
  `linux_resource_utilization` use the detector's reported period instead,
  capped at this many minutes.
- **`delta_signature_minutes`** — look-back for a signature alert.

The query filters on the agent only, not on IP or user, with two exceptions:
`log_volume` and `linux_resource_utilization` anomaly alerts use the anomalous
entity (`data.entity_keyword`) as the agent, and `suspicious_login` anomaly
alerts fetch the named user's events on any agent. Widen these windows if
the email or case lacks context. Narrow them if unrelated activity on the same
agent shows up in it.

---

## Tiers

Four tiers, T0 to T3. You set three boundaries; T3 always ends at 1.0.

| Tier | `ar.yaml` key | Response |
|------|---------------|----------|
| T0 | `0.0` → `tiers.tier1_min` | Nothing. The event is logged only |
| T1 | → `tiers.tier1_max` | Email notification + Flowintel case |
| T2 | → `tiers.tier2_max` | Email + Flowintel case + `mitigations_tier2` |
| T3 | → `1.0` | Full response + `mitigations_tier3` |

Boundaries must be non-decreasing. Setting two equal leaves that tier empty,
which is a legitimate way to disable a tier — e.g. `tier2_max = tier1_max`
means nothing ever lands in T2.

**`tier1_min` is your noise floor.** Anything below it is silently logged. Raise
it when you are getting emails you do not care about. The shipped `default`
scenario and `suspicious_login` both use `0.15`.

### Reachable tiers

With the shipped `ar.yaml`, these are the highest scores an alert can reach:

| Scenario | Highest score of a single alert | Tiers never reached |
|----------|---------------------------------|---------------------|
| `default` | 0.21 | T2, T3 (no mitigations configured) |
| `geoip_detection` | 0.54 (no CTI source) | T3 (`firewall-drop` already runs at T2) |
| `suspicious_login` | 0.468 for a signature alert, 0.6 for an anomaly alert (CTI score 1.0) | none, but T3 needs fusion (below) |
| `scanning_detection` | 0.678 (CTI score 1.0) | none |
| `log_volume`, `linux_resource_utilization` | 0.9 | none |

`suspicious_login` (`tier2_max: 0.55`):

- A signature alert alone reaches T2 only when DECIPHER returns a CTI score of
  at least 0.54 (failed-burst, credential-compromise and Office 365 rules) or
  0.73 (impossible-travel rules). It never reaches T3.
- T3 (`lock_user_linux.sh`) needs a signature alert combined with an anomaly:
  `0.3 × anomaly + 0.3 × CTI ≥ 0.382` for the failed-burst rule, for example an
  anomaly of 0.72 (grade 0.8 × confidence 0.9) with a CTI score of 0.56.
- An anomaly alert can reach T3 with a strong CTI score, but it names no IP or
  Linux user, so nothing is blocked or locked.

`geoip_detection` has no CTI source, so its CTI weight is 0 and `w_sig` is 1.0:
the strong rules (100900, 100901, 100903) score 0.54 (T2, `firewall-drop`).
100902 is not bound to the active response: it only feeds the frequency rule
100903 and never reaches `radar_ar.py`.

If you change weights or boundaries, recompute this table for your scenario and
re-validate it.

### Tuning workflow

1. Turn **Allow automatic mitigation execution** off. It ships on for
   `geoip_detection`, `suspicious_login`, `log_volume` and
   `linux_resource_utilization`.
2. Run for a few days. RADAR still plans and logs every action it *would* have
   taken.
3. Read `/var/ossec/logs/active-responses.log` and ask, for each entry: was this
   in the right tier?
4. Adjust:
   - too many emails → raise `tier1_min`
   - real incidents landing in T1 instead of T2 → lower `tier1_max`
   - one rule dominating → lower its `signature_likelihood` in the per-rule list
5. Only once the tiering looks right, enable automatic execution — and start
   with T3 mitigations only, leaving T2 empty.

---

## Mitigations

Available actions:

| Value in `ar.yaml` | Effect | Think twice when |
|--------------------|--------|------------------|
| `firewall-drop` | Blocks the alert's source IP on the affected agent | The source could be a NAT gateway, VPN concentrator, or your own office egress IP |
| `lock_user_linux.sh` | Locks the Linux account in the alert (never `root`, system accounts with UID < 1000, or protected users) | The account is a shared admin account (add it to `protected_users`) |
| `terminate_service.sh` | Stops the alert's service if it is allowlisted; otherwise kills processes connected to the alert's own source IP | The service or connection is something production depends on |

Assign them per tier on the RADAR Scenarios page (**+ Add action**). T0 and T1
cannot have actions.

Mitigation targets are taken from alert fields that anyone who can write a log
line can influence (a forged syslog program name, failed logins under a chosen
username). They are therefore restricted on both sides. An IP address or a user
that merely appears in the logs is never used as a target: only the source IP
and the user fields (`dstuser`, `srcuser`, `user`, `username`) of the alert
itself. An alert with no Linux user field, such as an Office 365 alert, locks
no account.

| Where | Setting | Effect |
|-------|---------|--------|
| Manager, `ar.yaml` (per scenario) | `terminable_services: [nginx, …]` | Only these services are ever sent to `terminate_service.sh`. Empty (default) = no service is stopped. |
| Manager, `ar.yaml` (per scenario) | `protected_users: [admin, …]` | These accounts are never sent to `lock_user_linux.sh`. `root` is always protected. |
| Agent | `/var/ossec/etc/radar-terminable-services` | One service per line; written by `bootstrap-agent.sh --allow-service <name>`. The agent refuses any service not listed. |
| Agent | `/var/ossec/etc/radar-protected-users` | Optional; one account per line that the agent never locks. |
| Manager, `ar.yaml` (top level) | `global.never_block: [10.0.0.1, 10.20.0.0/24, …]` | Addresses no mitigation may target. Add gateways, DNS servers, and admin subnets. Loopback, link-local, and the manager's own address are always protected. |
| Manager, `ar.yaml` (`scanning_detection`) | `trusted_proxies: [10.0.0.5, …]` | Reverse proxies or load balancers in front of your web servers. `X-Forwarded-For` is ignored unless the request came through one of them. |

A service must be in **both** lists to be stopped. Core services (`wazuh-*`,
`sshd`, `auditd`, `systemd-*`, firewall and syslog services) are never stopped,
whatever the lists say. Both agent scripts need `jq`, and refuse to act without it.

**`allow_mitigation`** is the master switch per scenario. Off means plan-and-log
only.

---

## Anomaly detector sensitivity

For ML scenarios, these live in `config.yaml` under the scenario, and take
effect the next time the detector is created.

| Parameter | Effect |
|-----------|--------|
| `anomaly_grade_threshold` | Minimum anomaly score to alert. Higher = fewer alerts |
| `confidence_threshold` | Minimum detector confidence to alert. Higher = more certainty required |
| `detector_interval` | How often the detector runs, in minutes. Lower = faster detection, more load |
| `shingle_size` | How many consecutive data points the model considers. Higher captures longer cycles; lower reacts faster to sudden changes |
| `categorical_field` | Gives each entity (user, agent) its own baseline instead of one global baseline |
| `monitor_max_entities` | How many anomalous entities one monitor run reports, highest grade first (default 5, at most 50). Each becomes its own alert |

Rules of thumb:

- **Too many false positives** → raise `anomaly_grade_threshold` and
  `confidence_threshold`.
- **Missing detections** → lower them, or shorten `detector_interval`.
- **Seasonal or weekly patterns** → raise `shingle_size`.
- **One noisy host swamping the baseline** → set `categorical_field` to
  `agent.name`.

Changing a detector parameter does not retune an existing detector. Delete the
detector from the Wazuh dashboard and re-run `./radar.sh run <scenario>`.
Monitor parameters (`anomaly_grade_threshold`, `confidence_threshold`,
`monitor_max_entities`, the trigger) are different: re-running
`./radar.sh run <scenario>` updates the existing monitor whenever they changed.