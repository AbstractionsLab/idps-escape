#!/bin/bash

# Define variables
USER=alab
CONTAINER_NAME=sonar-container
IMAGE_NAME=sonar:v0.7

# Define volume mounts
MODELS_VOLUME=$(pwd)/sonar/models:/home/$USER/soar/sonar/models
DATA_VOLUME=$(pwd)/sonar/test_data:/home/$USER/soar/sonar/test_data
SCENARIOS_VOLUME=$(pwd)/sonar/scenarios:/home/$USER/soar/sonar/scenarios
CONFIG_VOLUME=$(pwd)/sonar/default_config.yaml:/home/$USER/soar/sonar/default_config.yaml

# Run the Docker container with the specified arguments
docker run -it --rm --name $CONTAINER_NAME \
  -v $MODELS_VOLUME \
  -v $DATA_VOLUME \
  -v $SCENARIOS_VOLUME \
  -v $CONFIG_VOLUME \
  --network host \
  $IMAGE_NAME "$@"
