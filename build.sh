#!/bin/bash

SERVICE=${1:-all}

case $SERVICE in
  sonar)
    echo "Building SONAR image..."
    docker build -t sonar:v0.7 -f sonar/Dockerfile.sonar .
    ;;
  adbox)
    echo "Building ADBox image..."
    docker build -t adbox:v0.3.0 -f adbox/Dockerfile.adbox .
    ;;
  dev)
    echo "Building development image..."
    docker build -t soar-dev:latest -f dev.Dockerfile .
    ;;
  test)
    echo "Building test image..."
    docker build -t adbox-test:v0.3.0 -f adbox/Dockerfile.test .
    ;;
  all)
    echo "Building all images..."
    docker build -t sonar:v0.7 -f sonar/Dockerfile.sonar .
    docker build -t adbox:v0.3.0 -f adbox/Dockerfile.adbox .
    docker build -t soar-dev:latest -f dev.Dockerfile .
    docker build -t adbox-test:v0.3.0 -f adbox/Dockerfile.test .
    echo "All images built successfully!"
    ;;
  *)
    echo "Usage: ./build.sh {sonar|adbox|dev|test|all}"
    echo ""
    echo "Options:"
    echo "  sonar  - Build SONAR anomaly detection image"
    echo "  adbox  - Build ADBox v1/v2 image"
    echo "  dev    - Build development environment image"
    echo "  test   - Build testing image"
    echo "  all    - Build all images"
    exit 1
    ;;
esac

echo "Done."
