#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail

# GITHUB_WORKSPACE is set by actions/checkout@v3

export DOCKER_WORKSPACE_DIR="/root/$PROJECT_NAME"
export WORKSPACE_DIR=~/${PROJECT_NAME}_${DOCKER_IMAGE_SANITIZED}_${MTB_VERSION}

# Do not share the same workspace
cp -rf $GITHUB_WORKSPACE $WORKSPACE_DIR

docker run \
           --memory-swap -1 \
           --env WORKSPACE_DIR=$DOCKER_WORKSPACE_DIR \
           --env DOCKER_IMAGE=$DOCKER_IMAGE \
           --env DOCKER_IMAGE_SANITIZED=$DOCKER_IMAGE_SANITIZED \
           --env PROJECT_NAME=$PROJECT_NAME \
           --env MTB_VERSION=$MTB_VERSION \
           --env-file .github/docker/docker.env \
           -v "${WORKSPACE_DIR}:${DOCKER_WORKSPACE_DIR}" \
           ${DOCKER_REGISTRY}${DOCKER_IMAGE} \
           /bin/bash -c "${DOCKER_WORKSPACE_DIR}/.github/docker/script.sh"

exit 0
