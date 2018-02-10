#!/bin/bash
./container_command.sh coverage.sh
docker stop s1; docker rm s1;
