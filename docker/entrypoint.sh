#!/usr/bin/env bash

echo "start DoH proxy"

# read custom configuration
source /opt/doh-proxy/etc/.env

echo "doh-proxy: upstream dns server address: ${UPSTREAM_ADDR}:${UPSTREAM_PORT}"

/opt/doh-proxy/sbin/doh-proxy \
  --server-address=${UPSTREAM_ADDR}:${UPSTREAM_PORT} \
  --listen-address=0.0.0.0:3000 \
  --path=/dns-query
