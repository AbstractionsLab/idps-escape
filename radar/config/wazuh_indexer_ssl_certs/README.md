> **Note**: Please remember to populate this folder with the required SSL/TSL certificates, which can be generated as follows:
1. Adapt `config/certs.yml` according to your endpoints (IP address or container name).
2. Go back to `config` directory:
```bash
docker run --rm -it -v "$PWD/certs.yml:/config/certs.yml:ro" -v "$PWD/wazuh_indexer_ssl_certs:/certificates" wazuh/wazuh-certs-generator:0.0.2
```
3. Verify certificates in `config/wazuh_indexer_ssl_certs`.