sudo apt update
sudo apt install libgeoip-dev
sudo apt update && sudo apt install -y hping3 tshark iproute2
sudo setcap cap_net_raw,cap_net_admin=eip $(which hping3)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.12


geoip-1.3.2


docker run -d --name keycloak -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=secret \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev \
  --spi-events-listener-jboss-logging-enabled=true \
  --events-enabled=true \
  --events-expiration=3600 \
  --events-listener=jboss-logging


