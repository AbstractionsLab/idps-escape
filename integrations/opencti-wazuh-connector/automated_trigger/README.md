# Automated enrichment via triggers

For an analysis justifying the approach described here, see the [analysis](./ANALYSIS.md) file.

Automated enrichment in OpenCTI (`ar_opencti_enrich.py`) uses the OpenCTI GraphQL API to:

- Fetch all observables (paginated) from OpenCTI (`GetAllObservables`);
- Trigger enrichment for each observable via `StixCoreObjectEnrichmentLinesMutation` mutation;
- Runs asynchronously with retry/backoff.

This script can be used as:
1. An individual script for cron jobs.
2. A Wazuh Active Response. For this, the script should be placed into `/var/ossec/active-response/bin/` in the Wazuh Manager, and in `/var/ossec/etc/ossec.conf` add a command block:

```xml
<command>
  <name>enrich_opencti</name>
  <executable>ar_opencti_enrich.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```
Then, this active response will be linked to a **rule**.

## Environment variable requirements

1. `OPENCTI_API_URL`: The HTTP endpoint where your OpenCTI GraphQL API is listening.
Example: http://localhost:8080/graphql

2. `OPENCTI_API_TOKEN`: A valid API token (bearer token) for authenticating to OpenCTI.
You get this token from your OpenCTI user settings. It allows the script to call OpenCTI on your behalf.

3. `OPENCTI_CONNECTOR_ID`: The unique identifier of the OpenCTI connector you want to trigger (the “askEnrichment” connector).
You can find this ID in the OpenCTI UI under Connectors → Details for the connector you are using.

4. `CONCURRENCY_LIMIT`: The maximum number of concurrent API calls the script will make when triggering enrichments (defaults to 10). Increasing it makes more calls in parallel (faster), but uses more resources.

5. `REQUEST_TIMEOUT`: The maximum time (in seconds) to wait for any single HTTP request to OpenCTI before giving up. Defaults to 30. It helps the script avoid hanging indefinitely if OpenCTI is slow or unresponsive.