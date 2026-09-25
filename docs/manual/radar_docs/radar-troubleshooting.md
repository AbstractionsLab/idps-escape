# Troubleshooting

## GUI access

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Page does not load from another computer | The GUI accepts local connections only | Use an SSH tunnel: `ssh -L 5000:127.0.0.1:5000 <user>@<radar-host>` |
| "Not logged in" | Opened without the login token, or the GUI was restarted | Open the login URL printed in the GUI's terminal again |
| "Host … is not allowed" | Browsed by a name or address the GUI does not accept | Use `127.0.0.1:5000`, or add the name to `RADAR_GUI_ALLOWED_HOSTS` |

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

**Deployment fails on volume validation.** These container paths must be
bind-mounted: `/var/ossec/etc`, `/var/ossec/logs`, `/var/ossec/integrations`,
`/var/ossec/active-response/bin`, `/etc/filebeat`, and
`/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json`. Update
`volumes.yml` to match your manager — see
[Working with an existing Wazuh installation](./radar-getting-started.md#working-with-an-existing-wazuh-installation).

**`sudo` is requested even though the stack is already running.** Expected.
Applying a scenario's configuration to the manager needs `sudo` regardless of
whether the containers are up.

**The sudo password is asked for again.** It is checked when you enter it, kept
in memory only, and forgotten after 15 minutes without use or when the GUI
restarts.

**The build warns "stock default credentials still in use".** The deployment
still uses the stock Wazuh passwords. Run `sudo ./radar.sh rotate-credentials`.

**The Wazuh dashboard shows error 500 after a rebuild or credential change.**
The browser is sending an old login cookie. Open the dashboard in a private
window, or clear the site's data, then log in with the new `OS_PASS`.

## Anomaly detection

**No `log_volume` alerts arrive, and `docker logs ad-webhook` shows 401.** The
indexer's notification channel does not send the webhook's shared secret yet,
typically on a deployment set up before this was required. Run
`./radar.sh run log_volume` once to update the channel.

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
curl -k -u admin:<OS_PASS> https://localhost:9200/_cat/indices   # indices
tail -f /srv/wazuh/manager/logs/active-responses.log          # AR decisions
tail -f /srv/wazuh/manager/logs/ossec.log                     # manager log
```