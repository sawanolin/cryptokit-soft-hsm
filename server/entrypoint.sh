#!/bin/sh
set -eu

install -d -m 0700 -o sdfx -g sdfx /run/sdfx
install -d -m 0700 -o sdfx -g sdfx /var/lib/sdfx/web

umask 077
head -c 32 /dev/urandom > /run/sdfx/admin.token
chown sdfx:sdfx /run/sdfx/admin.token
chmod 0600 /run/sdfx/admin.token

exec /usr/bin/supervisord -c /etc/supervisord.conf
