#!/bin/bash
docker build --tag=challenge1 .
docker run -p 1337:1337 --rm --name=challenge1 challenge1