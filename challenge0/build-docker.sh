#!/bin/bash
docker build --tag=challenge0 .
docker run -p 1337:1337 --rm --name=challenge0 challenge0