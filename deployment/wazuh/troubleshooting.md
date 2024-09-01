# Troubleshooting


For start debugging for each component get the logs: 
```
docker compose -f docker-compose.yml logs -f wazuh.indexer 
```

To execute commands in the containers, you can execute the respective shell:

```
docker exec -it single-node-wazuh.manager-1 bash
```
```
docker exec -it single-node-wazuh.dashboard-1 bash
```
```
docker exec -it single-node-wazuh.indexer-1 bash
```

## Indexer

### securityadmin


If indexer logs contains

```
...
wazuh.indexer-1  | [2024-01-29T17:45:32,820][ERROR][o.o.s.a.BackendRegistry  ] [wazuh.indexer] Not yet initialized (you may need to run securityadmin)
...
```

within single-node-wazuh.indexer-1 bash copy

```
export INSTALLATION_DIR=/usr/share/wazuh-indexer

CACERT=$INSTALLATION_DIR/certs/root-ca.pem

KEY=$INSTALLATION_DIR/certs/admin-key.pem

CERT=$INSTALLATION_DIR/certs/admin.pem

export JAVA_HOME=/usr/share/wazuh-indexer/jdk
```
then 

```
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl
```

### Java heap size of OpenSearch and other setting

Depending on the expected data size the Java heap size might need adjustments. Similarly, other variables controlling setting of the OpenSearch distribution of Wazuh. 
This can be done setting in the corresponding variables in the `docker-compose.yml` file.

```
    environment:
      - OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk
      - OPENSEARCH_JAVA_OPTS=-Xms8g -Xmx8g
      - TZ=Europe/Luxembourg
```


## Agents

The version of the agents and central components must be compatible.

### Remove an agent

```
apt-get remove wazuh-agent
apt-get remove --purge wazuh-agent
```

If you want to completely remove all files, delete the `/var/ossec` folder.
Then, disable the service.

```
systemctl disable wazuh-agent
systemctl daemon-reload
```


To remove from dashboard you can use the API
https://documentation.wazuh.com/current/user-manual/agents/remove-agents/index.html