#!/bin/bash

SERVICE=${1:-all}

case $SERVICE in
  sonar)
    echo "Building SONAR image..."
    docker build -t sonar:v0.7 -f sonar.Dockerfile .
    ;;
  adbox)
    echo "Building ADBox image..."
    docker build -t adbox:v0.3.0 -f adbox.Dockerfile .
    ;;
  radar)
    echo "Building RADAR image..."
    docker build -t radar:v0.6 -f radar.Dockerfile .
    ;;
  dev)
    echo "Building development image..."
    docker build -t soar-dev:latest -f dev.Dockerfile .
    ;;
  test)
    echo "Building test image..."
    docker build -t adbox-test:v0.3.0 -f test.Dockerfile .
    ;;
  all)
    echo "Building all images..."
    docker build -t sonar:v0.7 -f sonar.Dockerfile .
    docker build -t adbox:v0.3.0 -f adbox.Dockerfile .
    docker build -t radar:v0.6 -f radar.Dockerfile .
    docker build -t soar-dev:latest -f dev.Dockerfile .
    docker build -t adbox-test:v0.3.0 -f test.Dockerfile .
    echo "All images built successfully!"
    ;;
  *)
    echo "Usage: ./build.sh {sonar|adbox|radar|dev|test|all}"
    echo ""
    echo "Options:"
    echo "  sonar  - Build SONAR anomaly detection image"
    echo "  adbox  - Build ADBox v1/v2 image"
    echo "  radar  - Build RADAR automation image"
    echo "  dev    - Build development environment image"
    echo "  test   - Build testing image"
    echo "  all    - Build all images"
    exit 1
    ;;
esac

echo "Done."
