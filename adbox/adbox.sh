#!/bin/bash

# Resolve paths relative to this script so it works from any invocation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define variables
USER=root
CONTAINER_NAME=adbox-container
IMAGE_NAME=adbox:v0.3.0

# Define volume mounts
ASSETS_VOLUME=$SCRIPT_DIR/assets:/home/$USER/adbox/assets
LOGS_VOLUME=$SCRIPT_DIR/logs:/home/$USER/adbox/logs

# Run the Docker container with the specified arguments
docker run -it --rm --name $CONTAINER_NAME \
  -v $ASSETS_VOLUME \
  -v $LOGS_VOLUME \
  --network host \
  $IMAGE_NAME "$@"
