#!/bin/bash
echo CyFORT-ADBox cleaning up...
docker stop siem-mtad-gat-container || true && docker rm siem-mtad-gat-container
docker rmi siem-mtad-gat:v0.1.0
echo Done.
