#!/bin/bash

# Resolve paths relative to this script so it works from any invocation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define variables
USER=alab
CONTAINER_NAME=sonar-container
IMAGE_NAME=sonar:v0.7

# Define volume mounts
MODELS_VOLUME=$SCRIPT_DIR/models:/home/$USER/soar/sonar/models
DATA_VOLUME=$SCRIPT_DIR/test_data:/home/$USER/soar/sonar/test_data
SCENARIOS_VOLUME=$SCRIPT_DIR/scenarios:/home/$USER/soar/sonar/scenarios
CONFIG_VOLUME=$SCRIPT_DIR/default_config.yaml:/home/$USER/soar/sonar/default_config.yaml

# Run the Docker container with the specified arguments
docker run -it --rm --name $CONTAINER_NAME \
  -v $MODELS_VOLUME \
  -v $DATA_VOLUME \
  -v $SCENARIOS_VOLUME \
  -v $CONFIG_VOLUME \
  --network host \
  $IMAGE_NAME "$@"
