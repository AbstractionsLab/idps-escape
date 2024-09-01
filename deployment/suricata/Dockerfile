# Dockerfile to build a Suricata docker container

# Set the base image to Ubuntu
FROM ubuntu:22.04

# File Author
MAINTAINER mzainab

# Update the repos
RUN apt update

# Allows us to add repositories
RUN apt install -y software-properties-common curl wget apt-transport-https jq nano 

# Add the Suricata repository
RUN add-apt-repository -y ppa:oisf/suricata-stable

# Update the repos and install Suricata
RUN apt update && apt install -y suricata

# Copy the suricata config to its config location
ADD suricata.yaml /etc/suricata/suricata.yaml

# Update the ruleset 
RUN suricata-update

# Copy the local rule file with our custom rules at the default location of suricata rules 
# This is only required while using a local ruleset 
# ADD local.rules /var/lib/suricata/rules/local.rules


# Start the Suricata service when the container is started
CMD service suricata start && tail -F /var/log/suricata/suricata.log

