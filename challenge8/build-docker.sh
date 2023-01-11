#!/bin/bash
docker build --tag=challenge8 .
docker run -p 1337:1337 --rm --name=challenge8 challenge8
