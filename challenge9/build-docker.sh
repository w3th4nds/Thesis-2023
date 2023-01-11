#!/bin/bash
docker build --tag=challenge9 .
docker run -p 1337:1337 --rm --name=challenge9 challenge9
