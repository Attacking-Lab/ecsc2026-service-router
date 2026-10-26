#!/bin/sh
cd "$(dirname "$(realpath "$0")")"
docker compose build
