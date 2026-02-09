#!/bin/bash

# Define variables
USER=root
CONTAINER_NAME=adbox-container
IMAGE_NAME=adbox:v0.3.0

# Define volume mounts
ASSETS_VOLUME=$(pwd)/adbox/assets:/home/$USER/adbox/assets
LOGS_VOLUME=$(pwd)/adbox/logs:/home/$USER/adbox/logs

# Run the Docker container with the specified arguments
docker run -it --rm --name $CONTAINER_NAME \
  -v $ASSETS_VOLUME \
  -v $LOGS_VOLUME \
  --network host \
  $IMAGE_NAME "$@"
