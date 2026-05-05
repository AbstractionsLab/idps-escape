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

Let $T \in [0,1]$ denote our CTI score, computed as specified in the system requirement specification [SRS-053](https://abstractionslab.github.io/satrap-dl/traceability/SRS.html#SRS-053) and the functional architecture scoring data flow diagram in [ARC-10](https://abstractionslab.github.io/satrap-dl/traceability/ARC.html#ARC-010) of the DECIPHER subsystem of [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl).

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