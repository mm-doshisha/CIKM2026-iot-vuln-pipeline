#!/bin/sh
set -e
: "${PARANOIA_LEVEL:=1}"
sed "s/__PARANOIA_LEVEL__/${PARANOIA_LEVEL}/g" \
    /etc/modsecurity/main.conf.tmpl > /etc/modsecurity/main.conf
echo "OWASP CRS commit: $(cat /etc/modsecurity/crs_commit.txt 2>/dev/null)"
echo "Paranoia level:   ${PARANOIA_LEVEL}"
nginx -t
exec nginx -g 'daemon off;'
