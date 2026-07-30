#!/bin/sh
set -eu

nc -z 127.0.0.1 18081
wget -q -T 3 -O /dev/null http://127.0.0.1:18080/api/health
