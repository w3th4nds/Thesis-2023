#!/bin/bash
docker build --tag=challenge6 .
docker run -p 1337:1337 --rm --name=challenge6 challenge6
