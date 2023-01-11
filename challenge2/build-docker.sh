#!/bin/bash
docker build --tag=challenge2 .
docker run -p 1337:1337 --rm --name=challenge2 challenge2
