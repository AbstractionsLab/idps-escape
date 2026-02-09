FROM ubuntu:24.04
ARG WAZUH_AGENT_VERSION
ARG WAZUH_MANAGER_ADDRESS
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python, and Wazuh Agent
RUN apt update && apt install -y \
    curl gnupg apt-transport-https lsb-release procps strace python3 python3-pip python3-flask \
 && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list \
 && apt update && WAZUH_MANAGER="${WAZUH_MANAGER_ADDRESS}" apt install -y "wazuh-agent=${WAZUH_AGENT_VERSION}" \
 && mkdir -p /var/log && touch /var/log/ad_alerts.log \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Copy webhook script
WORKDIR /app
COPY ad_alerts_webhook.py .
COPY ad-ossec.conf /tmp/ad-ossec.conf

RUN cat /tmp/ad-ossec.conf >> /var/ossec/etc/ossec.conf && rm /tmp/ad-ossec.conf

# Expose Flask port
EXPOSE 8080

# Start both the Wazuh agent and Flask webhook using supervisord
CMD /var/ossec/bin/wazuh-control start && python3 ad_alerts_webhook.py
