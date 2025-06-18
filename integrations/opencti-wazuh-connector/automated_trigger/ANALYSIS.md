# OpenCTI enrichment design analysis

## Option descriptions

- **Option 1:** Wazuh Active Response (AR) triggers the `opencti-wazuh-connector` with a specified anomaly detection window (start\_time to end\_time). The connector ingests alerts from this window and creates an Incident in OpenCTI with related observables and context.
    
- **Option 2:** The `wazuh-opencti-connector` pulls indicators from OpenCTI into Wazuh, allowing Wazuh to correlate incoming alerts with known IOCs.
    
- **Option 3:** The AR script queries all observables/indicators from OpenCTI and triggers enrichment per observable using the `StixCoreObjectEnrichmentLinesMutation()` GraphQL mutation.
    

### Comparison table

| Feature | Option 1 | Option 2 | Option 3 |
|---------|----------|----------|----------|
| CTI enrichment output | Incident and related context| CTI labels in Wazuh alerts|Enrichment of observables in OpenCTI |
|Dependency on connector change| Yes| No | No |
|Filtering requirement | By host | No | No |
| Risk of missing related data | High (limited time window) | Medium (no CTI feedback to OpenCTI) | Low (enriches each observable globally) |
| Scalability | Depends on alert volume | Scalable | Scalable using Async functions |
| Automation compatibility | High | Medium | High |

### Option 1

#### Pros

*   Creates structured Incident objects in OpenCTI tied directly to anomaly events.
*   Includes surrounding alerts, sightings, and notes, which are valuable for forensic analysis.
*   Good for contextual case creation and incident-driven CTI investigation.
    

#### Cons

*   Requires modification of the connector to support external context input. For example, the creation of an external file and monitoring its content for enrichment. The Connector does not have an API in place for usage. (e.g., `ad_ar_context.json`).
*   Alert data is limited to a time window, increasing risk of missing earlier or later related events.
*   Requires manual filtering (e.g., by agent ID or source) to maintain precision and relevance.
*   May be noisy in high-volume environments if anomaly triggers too many alerts.
    

### Option 2

#### Pros

*   Helps enrich Wazuh alerts with CTI labels and threat information.
*   Improves detection and alert correlation in Wazuh.
*   Simple to configure and maintain with no changes to OpenCTI.
    

#### Cons

*   Works in reverse direction; does not enrich OpenCTI.
*   Cannot create incidents, sightings, or STIX objects in OpenCTI.
*   Not aligned with the goal of OpenCTI-driven investigation and visibility.
    

### Option 3

#### Pros

*   Provides full enrichment coverage of all OpenCTI observables.
    
*   No time window limitations; captures alerts related to observables across all periods.
    
*   No connector changes required; uses OpenCTI’s native API (StixCoreObjectEnrichmentLinesMutation).
    
*   Can be scaled asynchronously, supporting large observable sets.
    
*   Ensures OpenCTI maintains an up-to-date threat graph with all known context.
    

#### Cons

*   Triggering enrichment individually for a large number of observables may introduce significant computational overhead, particularly if executed sequentially. However, this limitation can be mitigated by implementing asynchronous execution strategies (e.g., concurrent tasks using asynchronous I/O or multithreading), which allows multiple enrichment requests to be processed in parallel.
    

## Preferred option

We opt for **Option 3** as it ensures comprehensive and context-independent enrichment. Option 3 enriches each observable individually using the native OpenCTI enrichment logic, guaranteeing broader coverage and reduced dependency on event-specific context. Additionally, it stays within one ecosystem (Wazuh) and scales well with asynchronous execution.