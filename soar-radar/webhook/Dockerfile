FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python, and Wazuh Agent
RUN apt update && apt install -y \
    curl gnupg apt-transport-https lsb-release procps strace python3 python3-pip python3-flask \
 && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh-archive-keyring.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list \
 && apt update && apt install -y wazuh-agent=4.12.0-1 \
 && mkdir -p /var/log && touch /var/log/ad_alerts.log

# Copy webhook script
WORKDIR /app
COPY ad_alerts_webhook.py .
COPY ad-ossec.conf /var/ossec/etc/ossec.conf

# Expose Flask port
EXPOSE 8888

# Start both the Wazuh agent and Flask webhook using supervisord
CMD /var/ossec/bin/wazuh-control start && python3 ad_alerts_webhook.py
