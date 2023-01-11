#!/bin/bash
docker build --tag=challenge5 .
docker run -p 1337:1337 --rm --name=challenge5 challenge5
