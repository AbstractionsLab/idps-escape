# RADAR: Risk-aware Anomaly Detection-based Active Response scenarios

As a key part of the overall SOAR mission of IDPS-ESCAPE, in this folder, 
we store all design, development and implementation artifacts required for 
deploying our anomaly detection (AD) scenarios, along with their dedicated 
active responses (AR). Our security orchestration approach provides a series of Risk-aware AD-based AR (**RADAR**) modules aimed at enhancing SOC operations.

Our RADAR modules are currently geared towards an [Amazon AWS implementation](https://github.com/aws/random-cut-forest-by-aws/) of the classical [Random Cut Forest (RCF) AD on streams algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams) integrated into Wazuh, enabled by installing the [OpenSearch AD plugin](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/). We recommend a hybrid approach combining our [ADBox subsystem](/docs/manual/README.md) with our RCF-based [RADAR subsystem](/soar-radar/README.md) for a more robust setup, providing [resilience to adversarial interference](#best-practices-for-robust-ad-with-resilience-to-adversarial-interference).

We make use of the latest advances in the [OpenSearch implementation](https://opensearch.org/anomaly-detection/), namely [false positive reductions](https://opensearch.org/blog/reducing-false-positives-through-algorithmic-improvements/) and support for categorical features and [high-cardinality anomaly detection](https://aws.amazon.com/blogs/big-data/detect-anomalies-on-one-million-unique-entities-with-amazon-opensearch-service/) via slicing, allowing for separate baseline detectors that avoid statistical artifacts, e.g., UEBA model baselines per user or device to avoid deviations in one user behavior to be masked by another's when performing AD in a group setting.

We recommend adopting our hybrid method aimed at robustness and resilience to adversarial interference involving three elements: (i) signature-based detection with (ii) AD based on deep learning models via MTAD-GAT using ADBox, relying on state-of-the-art advances in artificial intelligence (AI) and machine learning (ML) such as the *attention mechanism* and (iii) a classical algorithm for AD on streams such as the Robust Random Cut Forest (RRCF) algorithm supporting categorical features.

Below we provide a mapping of each key feature to their corresponding 
scripts, configurations, and components in the repository.

## Prerequisites

- The [OpenSearch AD plugin integrated into Wazuh](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/), which is based on the classical [Random Cut Forest (RCF) AD on streams algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams): see our dedicated [installation page](/deployment/opensearch-ad-plugin.md) for more details on a Docker-based approach to adding the OpenSearch AD plugin to Wazuh.
- Optionally, our [ADBox](/docs/manual/README.md) subsystem for a hybrid approach to AD.

## RADAR scenarios

Currently implemented RADAR scenarios include:

- [Insider threat](/soar-radar/insider_threat/)

These provide and make use of the following:

- `wazuh_ingest.py`: Parses datasets and ingests into a Wazuh index.
- Detector, monitor, webhook, decoder, rule, active response implementations.

Together, these form RADAR detectors and response modules for 
deploying machine learning-based AD coupled with automated response.

## Active response modules and SOAR playbooks for Wazuh

The [active response](/soar-radar/active_responses/) modules stored at `soar-radar/active_responses` provide 
automated responses and contextual enrichments based on anomalies. 
These reduce manual work for analysts via automation and also benefit from our [CTI integration](/integrations/README.md) support.

## Best practices for robust AD with resilience to adversarial interference

In a future update, we will provide a detailed report on how to implement the main defensive mechanisms based on state-of-the-art research on adversarial machine learning and anomaly detection. Here we provide some concise notes on how to tackle this following our recommended hybrid approach combining the use of both our MTAD-GAT paradigm in the ADBox subsystem as well as the classical RCF-based AD solution available via an OpenSearch plugin.

### Practical implementation considerations

Translating the latest research findings into practice within SIEM and SOC operations would involve the following considerations:

#### Baseline initialization

We recommend initializing anomaly detection models on data believed to be clean. For example, train on logs from a honeypot-free period or using a gold-standard dataset. If there is any suspicion that an attacker was present historically, those time segments or hosts should be excluded or given lower weight in initial training. Some organizations perform “digital clean room” exercises – temporarily locking down systems to capture a clean baseline. While not always feasible, the cleaner the start, the more reliable the model.
    
#### Continuous retraining with caution

Anomaly models based on deep learning often need retraining or updating as systems and usage patterns evolve. However, blindly retraining on recent data can incorporate an attacker’s ongoing behavior. A practical compromise is to use a rolling training window but with **concept drift detection**. If the baseline shifts too quickly or in a strange way, freeze the model and have an analyst examine the change before accepting it. This prevents an attacker from gradually shifting the baseline (“boiling the frog”) without notice.
    
#### Use of contamination parameter

Some of the off-the-shelf anomaly detection algorithms (e.g., IsolationForest in Python’s scikit-learn or the PyOD library) allow specifying an expected contamination rate. We can leverage this by setting a small contamination fraction (based on threat modelling – perhaps 1-5%). This ensures the model inherently treats the top few percent most abnormal training points as outliers. It is a simple safeguard: even if an attacker’s data got in, the model might naturally down-rank it as part of that fraction. One must be careful to neither underestimate nor grossly overestimate this fraction; tuning on validation data or known-clean subsets can help. **Note**: Our current release does not provide an immediate way of enforcing the above, but if you feel inclined to do so, the ingredients are all available in the repository.
    
#### Synthetic anomaly injection

To test and improve the detector’s sensitivity, security teams can inject simulated anomalies or red-team activities during training or evaluation. If the model fails to flag these injections, that indicates an overfitting or poisoned baseline problem. Some organizations periodically run adversarial drills (e.g., a benign worm simulation) and check if the anomaly detector catches it. Such tests, inspired by adversarial training, can expose weaknesses in the model’s learned normalcy and prompt retraining with the injected anomalies included as “anomalous”. Essentially, this is a way to vaccinate the model against certain attacks.
    
#### Multi-layer logging and detection

Ensuring that logs from different layers (network, OS, application) are available and anomaly detection is applied to each can reveal inconsistencies. For example, an attacker might manage to poison host logs but not network flows. If the SIEM aggregates and compares both, the anomaly in one can reveal the stealth in the other. Implementing a unified view (via user and entity behavior analytics – UEBA – that spans multiple log types) is a practical way to achieve the hybrid approach discussed. Our approach already provides UEBA modules that learn behavior baselines per user or device across diverse activities; these can act as a backstop if any single log source is compromised.
    
#### Alert fusion and analyst workflows

In practice, dealing with outputs from these advanced anomaly detectors requires good workflow design. If robust methods are used, they might produce a lot of information – e.g., which points were considered outliers and dropped, or which small anomaly set was used. This information should be exposed to analysts (possibly as explanations for why something is deemed normal or anomalous). For instance, if an alert is suppressed because the model thinks “this is normal for that host,” an analyst might want to see what baseline data supports that belief. Transparency can help catch cases where the model was tricked.
    
#### System hardening

Adversaries sometimes try not just to poison data but to tamper with the detection system (for example, by altering log integrity or even the model files if they gain access). So traditional security controls are important: ensure **log integrity** (cryptographic hashing, append-only logging) to prevent an attacker from retroactively sanitizing their traces; restrict access to the ML model and training pipeline (only authorized administrators can initiate retraining, etc.). These measures do not directly solve the ML challenge but create additional hurdles for an attacker attempting to carry out a poisoning attack.

#### Additional remarks

In general, we recommend a combination of _technical controls_ (robust algorithms, multi-source detection) and _process controls_ (human oversight, data validation procedures).

Over the past decade, we have been observing a trend: awareness of adversarial threats to IDS has risen, and solutions are becoming more sophisticated – from simply cleaning the data to proactively _learning_ in the presence of malicious influence. The overarching goal is to ensure that an attacker cannot easily hide in the “noise” of normalcy nor quietly teach our defenses to ignore them. 

While there is still a need for more robust and resilient AD solutions and a gap in fully addressing adaptive adversaries, the strategies outlined above – data sanitization, robust training (with help from a few labelled anomalies or adversarial learning), hybrid detection layers, and human-in-the-loop (HITL) oversight – collectively form a basis to meet the challenge of adversaries corrupting anomaly detection systems. With such measures being in place, turning an AD system against itself can be made harder for an infiltrator.