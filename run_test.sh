#!/bin/bash

# Define variables
USER=root
CONTAINER_NAME=adbox-container-test
IMAGE_NAME=adbox-test:v0.3.0

# Define volume mounts
ASSETS_VOLUME=$(pwd)/adbox/assets:/home/$USER/adbox/assets
LOGS_VOLUME=$(pwd)/adbox/logs:/home/$USER/adbox/logs

# Run the Docker container with the specified arguments
docker run -it --rm --name $CONTAINER_NAME \
  -v $ASSETS_VOLUME \
  -v $LOGS_VOLUME \
  --network host \
  $IMAGE_NAME "$@" 
  # if no argument given run all tests other specify test file as tests/{name}_test.py