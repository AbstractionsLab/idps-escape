# Troubleshooting

## Connectors

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Connection refused | Wrong port, or the service is not running | Verify URL and port; confirm the container is up |
| SSL certificate error | Self-signed certificate with no CA uploaded | Enable SSL verification on the card and upload the CA `.pem` / `.crt` |
| 401 Unauthorized | Wrong credentials | Re-enter, **Save**, then **Test** again |
| Timeout | Firewall between the RADAR host and the service | Check network rules |
| MaxMind key rejected | Key is for the wrong product, or not yet active | Regenerate from the MaxMind account's *My License Key* page |

Connector values live in `.env`.

## Deployment

**Deployment fails on volume validation.** These three container paths must be
bind-mounted: `/var/ossec/etc`, `/var/ossec/active-response/bin`,
`/etc/filebeat`. Update `volumes.yml` to match your manager — see
[Working with an existing Wazuh installation](./radar-getting-started.md#working-with-an-existing-wazuh-installation).

**`sudo` is requested even though the stack is already running.** Expected.
Applying a scenario's configuration to the manager needs `sudo` regardless of
whether the containers are up.

**The sudo password is asked for again.** It is held in memory for the browser
session only. Restarting the Flask server clears it.

## Agents

**`agent-auth` fails with connection refused on port 1515.** The enrollment
window is closed. Minting a token opens it automatically; if you are enrolling
without minting, open it first:

```bash
sudo ./radar.sh enrollment open --minutes 30
```

**"Duplicate agent name".** The manager runs with `purge=no`, so an enrollment
using an already-registered name is rejected rather than silently replacing the
existing agent. Deregister the old entry first (Agent Management → Deregister
agent), or bootstrap with a different `--agent-name`.

**A deregistered agent keeps coming back.** The Wazuh agent service is still
running on the endpoint and re-enrolling. Stop it there first.

**Group Management cannot find the agent.** Resolution is tried by IP, then by
name. Confirm the IP is right and that `bootstrap-agent.sh` actually completed;
otherwise supply the exact name the agent registered under from Wazuh Dashboard.

**An agent is in the group but produces no `log_volume` events.** Group
assignment delivers config but not the systemd timer that writes the metric.
Re-run `bootstrap-agent.sh --group log_volume` on that endpoint.

## Useful commands

```bash
docker ps                                    # what is running
docker logs wazuh.manager                    # manager container
docker logs ad-webhook                       # webhook service
curl -k -u admin:<pass> https://localhost:9200/_cat/indices   # indices
tail -f /srv/wazuh/manager/logs/active-responses.log          # AR decisions
tail -f /srv/wazuh/manager/logs/ossec.log                     # manager log
```