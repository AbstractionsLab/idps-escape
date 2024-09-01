# Change user password

### Setting a new hash

Stop the deployment stack if it’s running:

```sh
docker-compose down
```

Run this command to generate the hash of your new password. Once the container launches, input the new password and press **Enter**.

```sh
docker run --rm -ti wazuh/wazuh-indexer:4.7.2 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```
   
Copy the generated hash.

```sh
Password:
********
Hash:
$2y$12$17tj6r7gWRrLqxlB8wVKluqSM5PmNJCgyGR9CSZwTecTUdbkScyoa
```

Open the `config/wazuh_indexer/internal_users.yml` file. Locate the block for the user you are changing password for (`admin`, `kibanaserver`).

```sh
admin:
	  hash: "$2y$12$17tj6r7gWRrLqxlB8wVKluqSM5PmNJCgyGR9CSZwTecTUdbkScyoa"
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"

kibanaserver:
  hash: "$2y$12$17tj6r7gWRrLqxlB8wVKluqSM5PmNJCgyGR9CSZwTecTUdbkScyoa"
  reserved: true
  description: "Demo kibanaserver user"
```

### Setting new password

In the `docker-compose.yml` file. Change all occurrences of the old password with the new one.

```YAML
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=********
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
      - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
      - SSL_KEY=/etc/ssl/filebeat.key
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-
    volumes:
....
    image: wazuh/wazuh-dashboard:4.7.2
    hostname: wazuh.dashboard
    restart: always
    ports:
      - 443:5601
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=********
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=********
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-


```

#### Apply changes

```sh
docker-compose up -d
docker exec -it single-node-wazuh.indexer-1 bash
```

Insider the indexer:

```
export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
```

Then, run the `securityadmin.sh` script to apply all changes:

```sh
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl
```

__The last script is essential to start the index!__

#### Troubleshooting

If when restarting the dashboard you get the error: `{"statusCode":500,"error":"Internal Server Error","message":"An internal server error occurred."}`, it might be a caching-related problem of Firefox. Try in incognito mode.
