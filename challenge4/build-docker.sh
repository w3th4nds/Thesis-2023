#!/bin/bash
docker build --tag=challenge4 .
docker run -p 1337:1337 --rm --name=challenge4 challenge4