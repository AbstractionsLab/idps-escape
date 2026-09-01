# Tuning detection and response

Everything here is edited on the **RADAR Scenarios** page of the GUI, or
directly in `scenarios/active_responses/ar.yaml`. Per-scenario values override
the `default` scenario's values; anything you leave unset is inherited.

---

## How the risk score is built

Every alert gets a score in `[0, 1]` combining up to three sources, weighted:

```
risk  =  w_ad · (anomaly_grade × confidence)
       + w_sig · (signature_impact × signature_likelihood)
       + w_cti · cti_score
```

`w_ad + w_sig + w_cti` must equal 1.0.

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

If DECIPHER is not running, move `w_cti` into the other weights rather than
leaving it — a CTI weight with no CTI source drags every score down.

---

## Signature scoring

- **`signature_impact`** — how bad it is if this rule is right. A rule that
  detects account lockout is not as impactful as one that detects a root shell.
- **`signature_likelihood`** — how often this rule is right. Chatty rules with
  many false positives belong low.

`ar.yaml` also accepts a per-rule form, which is what **every shipped scenario
except `log_volume` uses**:

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

- **`delta_ad_minutes`** — when an anomaly fires, how many minutes of history
  RADAR searches for related detector events.
- **`delta_signature_minutes`** — how far back RADAR looks for signature events
  and CTI hits on the same entity (IP, user, hostname).

Widen these if related events are arriving slightly out of order or if your
detector interval is long. Narrow them if unrelated activity is being pulled
into the correlation.

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
scenario uses `0.15`; `suspicious_login` uses `0.2`.

### Tuning workflow

1. Leave **Allow automatic mitigation execution** off.
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
| `firewall-drop` | Blocks the source IP on the affected agent | The source could be a NAT gateway, VPN concentrator, or your own office egress IP |
| `lock_user_linux.sh` | Locks the Linux account in the alert (never `root`) | The account is a service account or a shared admin account |
| `terminate_service.sh` | Terminates the suspicious process or service | The process is something production depends on |

Assign them per tier on the RADAR Scenarios page (**+ Add action**). T0 and T1
cannot have actions.

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

Rules of thumb:

- **Too many false positives** → raise `anomaly_grade_threshold` and
  `confidence_threshold`.
- **Missing detections** → lower them, or shorten `detector_interval`.
- **Seasonal or weekly patterns** → raise `shingle_size`.
- **One noisy host swamping the baseline** → set `categorical_field` to
  `agent.name`.

Changing a detector parameter does not retune an existing detector. Delete the
detector from the Wazuh dashboard and re-run `./radar.sh run <scenario>`.