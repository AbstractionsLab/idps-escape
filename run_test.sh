#!/bin/bash

# Define variables
USER=root
CONTAINER_NAME=siem-mtad-gat-container-test
IMAGE_NAME=siem-mtad-gat-test:v0.1.4

# Define volume mounts
ASSETS_VOLUME=$(pwd)/siem_mtad_gat/assets:/home/$USER/siem-mtad-gat/siem_mtad_gat/assets
LOGS_VOLUME=$(pwd)/siem_mtad_gat/logs:/home/$USER/siem-mtad-gat/siem_mtad_gat/logs

# Run the Docker container with the specified arguments
docker run -it --rm --name $CONTAINER_NAME \
  -v $ASSETS_VOLUME \
  -v $LOGS_VOLUME \
  --network host \
  $IMAGE_NAME "$@" 
  # if no argument given run all tests other specify test file as tests/{name}_test.py