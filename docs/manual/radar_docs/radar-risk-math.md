# RADAR lightweight risk engine

Here we specify the mathematics of a practitioner‑oriented design for a normalized, sound and efficient risk engine that is implemented in our Wazuh Active Response (AR) script and integrates:

*   **RRCF anomaly detector outputs** (anomaly grade *G*, confidence *C*) and SONAR indicators in a future update
*   **Signature-based likelihood/impact values** (L, I)
*   **CTI boolean flags** (various enrichments)
*   **Optional heuristics and dynamic learning improvements**

We provide a simple formula, explain how it addresses various criteria, show how each subsystem contributes, and propose several enhancements commonly used in modern SOAR/SIEM pipelines that we may implement in future updates.

## Objectives for the risk engine

The final risk engine should:

1.  Produce a **normalized risk score** $\in [0,1]$.
2.  Allow natural decision boundaries for **LOW**, **MEDIUM**, **HIGH** tiers.
3.  Combine anomalies from RRCF and MTAD-GAT + signature-based detection data + CTI in a mathematically consistent way.
4.  Be simple, lightweight and fast enough to run inside an **Active Response script** (bash, Python, etc.).
5.  Be tunable and extensible.

## Inputs and notation

### **RRCF-based anomaly detector**

*   Anomaly Grade: $G \in [0,1]$
*   Confidence: $C \in [0,1]$

We combine these as:  
$$
A = G \times C
$$
and use $A$ as an anomaly “intensity” metric. In a later release combining RADAR and SONAR signals for a hybrid detection approach, this will also incorporate similar indicators from the MTAD-GAT algorithm used in our SONAR subsystem.

### **Signature-based detection**

We assign a **likelihood** $L \in [0,1]$ and **impact** value $I \in [0,1]$ to each RADAR scenario, which can be combined as:  
$$
S = L \times I.
$$

This simply mirrors standard (e.g. ISO‑based) risk concepts (risk ≈ likelihood × impact).

### **CTI subsystem**

The DECIPHER subsystem of SATRAP-DL will provide RADAR with boolean indicators such as:

*   `is_ip_blacklisted`
*   `is_domain_malicious`
*   `is_user_compromised_flagged`
*   `is_hash_malicious`
*   etc.

Each boolean can be mapped to a weight or severity multiplier.

Let $T \in [0,1]$ denote our CTI score, defined as follows:  

Example mapping:

| CTI flag                | Weight |
| ----------------------- | ------ |
| Blacklisted IP          | 0.6    |
| Known malicious hash    | 0.7    |
| Domain in threat feed   | 0.4    |
| User flagged suspicious | 0.5    |

We define a simple aggregator over $n$ CTI indicator weights: 
$$
T = 1 − \prod_i^n (1 − w_i)
$$

This produces 0 if no CTI hits, and approaches 1 as more indicators pile up.

## A practical combined risk formula

### **Final risk score:**

$$
\boxed{
R = w_A \cdot A + w_S \cdot S + w_T \cdot T
}
$$

where:

*   **A** = anomaly intensity
*   **S** = signature‑based risk
*   **T** = CTI evidence score
*   $w_A + w_S + w_T = 1$ (providing normalization)

We can define and adjust these weighting and normalization terms, with a possible starting point for weights given below (used as default values in our implementation):

*   $w_A = 0.4$ (behavioral → high information value)
*   $w_S = 0.4$ (signature → high precision but limited recall)
*   $w_T = 0.2$ (CTI → confirmatory, reduces false positives)

We can tune these based on operational experience and SOC requirements.

## Tiering the risk score

The tiering mechanism in RADAR revolves around our risk score, which can be empirically studied and adapted.

### Suggested thresholds:

*   **Low risk** $(0.0 \le R < 0.33)$

    → Email only

*   **Medium risk** $(0.33 \le R < 0.66)$

    → Email + case creation + light response

*   **High risk** $(0.66 \le R \le 1.0)$

    → Notifications + case + strong action (block, isolate, disable credential)

These thresholds can also be calibrated using historical logs and adjusted in the `ar.yaml` file.

## Concrete example calculation

Suppose:

* $G = 0.62$, $C = 0.74$ → $A = 0.4588$
* Likelihood $L = 0.4$, Impact $I = 0.9$ → $S = 0.36$
* CTI hits:
  * Blacklisted IP (0.6)
  * Suspicious domain (0.4)

Then:

$$
T = 1 - (1 - 0.6)(1 - 0.4) = 1 - 0.4 \times 0.6 = 1 - 0.24 = 0.76
$$

Finally:

$$
R = 0.4 A + 0.4 S + 0.2 T  
= 0.4 (0.4588) + 0.4 (0.36) + 0.2 (0.76)
$$

$$
= 0.1835 + 0.144 + 0.152 = 0.4795
$$

which allows to determine the **risk tier** as **medium**.

System response → email + case + light containment.

## Summary

The proposed design provides a model that is mathematically sound, SOC-friendly, and CTI-aware. Moreover:

* It combines anomaly, signature, and CTI-based indicators;
* All values are normalized;
* It is extensible and easily calibrated;
* It is suitable for real-time computation within Wazuh Active Response scripts.

Features that may be implemented in future releases are discussed in a [dedicated page](/docs/manual/radar_docs/radar-risk-engine-roadmap.md).

### Advantages

The advantages of our model include:

* Normalization: all inputs stay in $[0,1]$, producing predictable behavior.
* Decoupled, YAML‑configurable: no hardcoded rule logic inside Python.
* Pluggable into Wazuh AR: only requires standard Python + pyyaml.
* Extensible: Add new CTI flags, new risk modifiers, or new rules with no or very little code change.

## YAML configuration (rule → weights and settings)

We maintain an [ar.yaml](/radar/scenarios/active_responses/ar.yaml) configuration file, which implements the above-mentioned parameters.