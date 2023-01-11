#!/bin/bash
docker build --tag=challenge7 .
docker run -p 1337:1337 --rm --name=challenge7 challenge7
