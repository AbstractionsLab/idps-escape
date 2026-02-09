# RADAR risk engine roadmap

## CTI boolean integration (detailed)

We briefly discuss three approaches for incorporating CTI input from the DECIPHER subsystem of SATRAP-DL.

- Option A — **Additive** CTI score (already discussed in the [main RADAR risk engine specification](./radar-risk-math.md))
- Option B — **Multipliers** on risk (currently not implemented)
- Option C — "**Gates**" (currently not implemented)

### How to incorporate CTI booleans effectively

#### Option A - additive CTI score

See our definition [above](./radar-risk-math.md).

#### Option B - multipliers on risk

Example: if RRCF+signature risk is given by $R_0$, then:

$$
R = R_0 \cdot (1 + T)
$$

clamped to $[0,1]$.

This can be viewed as causing CTI hits to “boost” the risk.

Example:  

$R_0 = 0.45$, $T = 0.3$ → $R = 0.585$ (now medium/high threshold)

#### Option C — “Gates”

For some CTI signals, we may choose:

*   If `known_malicious_hash == true` → force MIN risk of $0.75$
*   If `ip_blacklisted == true` → force MIN risk of $0.5$
*   etc.

This would avoid cases where a highly malicious IOC is underestimated.

## Improving the risk engine (on the roadmap)

The following ideas are currently not implemented, but we may include them in future releases.

### Temporal persistence weighting

If anomalies repeat:

* Increase risk nonlinearly or exponentially for repeated events.
* Implement a decay function for past events (e.g., exponential decay with half-life).

### Rare-event amplification

Anomalies with high **confidence** but low grade can still matter. We can adjust:

$$
A = G^\alpha \times C^\beta
$$

with $\alpha < 1$ or $\beta > 1$ to adjust sensitivity.

### Per‑user or per‑asset baselines

We can make the system more accurate by normalizing anomaly scores per entity:

* User-level profiles
* Host-level profiles
* Network-segment profiles

### Contextual risk modifiers

Add weights based on local business context:

| Context                       | Modifier |
| ----------------------------- | -------- |
| VIP user                      | +0.15    |
| Crown jewel asset             | +0.30    |
| External network              | +0.10    |
| Privilege escalation involved | +0.20    |

These can be added into $S$ (signatures) or applied multiplicatively to $R$.

### Confidence propagation

Propagate low-confidence CTI labels or uncertain anomaly signals as “soft boosts” rather than hard booleans.

### Track risk over a sliding window

Instead of reacting on single events, maintain:

$$
R_C = \max(R_N, RPE)
$$

where $R_C$ denotes cumulative risk, $R_N$ current risk value, $RPE$ representing the rollup past $n$ events. 

This may turn out to be effective for APT-style stealthy attacks.