# Getting started: Full stack deployment guide

This guide provides step-by-step instructions for deploying the complete IDPS-ESCAPE stack, including signature-based intrusion detection (Suricata), SIEM & XDR (Wazuh), and anomaly detection components (SONAR/ADBox).

## Deployment options

### Option 1: Automated deployment (Recommended)

For rapid deployment of RADAR with integrated Wazuh manager and agents:

```bash
cd radar
./build-radar.sh <scenario> --agent <local|remote> --manager <local|remote> --manager_exists false
```

See the [RADAR README](/radar/README.md) for detailed usage and scenario options.

### Option 2: Manual step-by-step integration

Use this approach if you have existing Wazuh infrastructure or need custom configuration.

## Step-by-step manual deployment

## Step-by-step manual deployment

### Prerequisites

- Docker and Docker Compose installed on target hosts
- Ansible 2.15+ (if using automation features)
- Network connectivity between components
- Sufficient resources: ~4-8 GB RAM per subsystem, ~26 GB storage total

### Step 1: Deploy Suricata (Network IDS)

**Purpose:** Enable network-level monitoring and intrusion detection.

**Installation options:**

a. **Containerized environment:** Follow [Suricata installation guide](../../deployment/suricata/suricata_installation.md#installation-and-configuration-of-suricata)

b. **Configuration:** Adapt to your local network using the [configuration guide](../../deployment/suricata/suricata_installation.md#suricata-configuration-file)

### Step 2: Deploy Wazuh central components (SIEM & XDR)

**Purpose:** Centralized log collection, event correlation, and security monitoring.

**Installation:**

a. **Deploy Dashboard, Manager, and Indexer:** Follow [Wazuh installation guide](../../deployment/wazuh/wazuh_installation.md) for containerized deployment

b. **Configure for your environment:** Complete [system configuration steps](../../deployment/wazuh/wazuh_installation.md#next-steps)

### Step 3: Deploy Wazuh agents (Host monitoring)

**Purpose:** Monitor endpoint activity, file integrity, and host-level events.

**Installation:**

a. **Primary host agent:** Follow [Wazuh agent installation](../../deployment/wazuh/wazuh_agents.md)

b. **Additional endpoints (optional):** Deploy agents on other systems following the same procedure

c. **Remote traffic monitoring (optional):** Enable [remote monitoring capabilities](../../deployment/remote_monitoring/remote_monitoring.md)

### Step 4: Integrate Suricata with Wazuh

**Purpose:** Unified network and host event correlation in SIEM.

Follow the [Suricata-Wazuh integration procedure](../../deployment/integration.md) to:
- Configure Wazuh to ingest Suricata alerts
- Set up log forwarding and parsing
- Enable unified dashboard visibility

**Benefits:**
- Joint monitoring of host and network events
- Centralized storage and analysis
- Correlated alerting across detection layers

### Step 5: Deploy anomaly detection (SONAR or ADBox)

**Purpose:** ML-based anomaly detection on centralized SIEM data.

**Option A: SONAR (Production - Recommended)**

```bash
# Install SONAR
poetry install --with sonar

# Configure Wazuh connection
# Edit sonar/default_config.yaml with your Wazuh credentials

# Verify connection
poetry run sonar check

# Run detection scenario
poetry run sonar scenario --use-case sonar/scenarios/example_scenario.yaml
```

See [SONAR setup guide](./sonar_docs/setup-guide.md) for detailed configuration.

**Option B: ADBox (Research/Legacy)**

```bash
# Build Docker image
./build-adbox.sh

# Configure Wazuh connection
# Edit adbox/assets/secrets/wazuh_credentials.json

# Verify connection
./adbox.sh -c

# Run detection use-case
./adbox.sh -u 1
```

See [ADBox installation guide](./adbox_docs/adbox_installation.md) for details.

## Verification

After deployment, verify the integrated stack:

1. **Suricata alerts** appear in Wazuh Dashboard
2. **Host agents** reporting to Wazuh Manager
3. **SONAR/ADBox** successfully connects to Wazuh Indexer
4. **Detection scenarios** execute without errors

## Architecture overview

```
┌─────────────┐
│   Suricata  │ (Network IDS)
└──────┬──────┘
       │ network alerts
       ↓
┌─────────────────────────────────────┐
│         Wazuh Manager               │ (SIEM & XDR)
│  ┌──────────────┐  ┌─────────────┐ │
│  │ Log Collector│  │ Rule Engine │ │
│  └──────────────┘  └─────────────┘ │
└────────────┬────────────────────────┘
             │ indexed alerts
             ↓
┌─────────────────────────────────────┐
│      Wazuh Indexer (OpenSearch)     │
└────────────┬────────────────────────┘
             │ query alerts
             ↓
┌─────────────────────────────────────┐
│    SONAR / ADBox (Anomaly Det.)     │
│         ↓ anomalies ↓               │
│    Wazuh Data Streams (RADAR)       │
└─────────────────────────────────────┘
```

## Next steps

- Configure [RADAR scenarios](/radar/README.md) for automated response
- Set up [data shipping](./sonar_docs/data-shipping-guide.md) for production SONAR deployments  
- Integrate [CTI tools](/integrations/README.md) (MISP, OpenCTI)
- Create custom [Wazuh dashboards](./adbox_docs/dashboard_tutorial.md)

## Troubleshooting

**Common issues:**

- **Connection errors:** Verify Wazuh Indexer SSL certificates and credentials
- **No Suricata alerts:** Check Suricata-Wazuh integration configuration  
- **Agent not reporting:** Verify network connectivity and Wazuh Manager address
- **SONAR/ADBox failures:** See respective troubleshooting guides ([SONAR](./sonar_docs/troubleshooting.md), [ADBox](./adbox_docs/adbox.md))

For detailed troubleshooting, consult component-specific documentation.

## Reference documentation

- [RADAR architecture](/docs/manual/radar_docs/radar-architecture.md)
- [SONAR documentation](./sonar_docs/README.md)
- [Deployment details](../../deployment/README.md)
- [Integration guide](/integrations/README.md)
