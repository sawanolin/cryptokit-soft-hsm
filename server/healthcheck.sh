#!/bin/sh
set -eu

wget -q -T 3 -O /dev/null http://127.0.0.1:18080/api/health
