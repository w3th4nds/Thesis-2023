#!/bin/bash
docker build --tag=challenge3 .
docker run -p 1337:1337 --rm --name=challenge3 challenge3
