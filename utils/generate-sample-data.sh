#!/usr/bin/env bash

TMP_FILE="/var/spool/proxyble/rules/inbox.tmp"
RULE_DIR="$(dirname -- "$TMP_FILE")"

# Number of loops. Each loop writes one temporary and one persistent sample for
# each supported action.
LOOPS=${1:-1}

mkdir -p "$RULE_DIR"
BATCH_FILE="$(mktemp "$RULE_DIR/inbox.sample.XXXXXX")"
trap 'rm -f "$BATCH_FILE"' EXIT

PREFIX="192.0"

for ((i=1; i<=LOOPS; i++)); do

    # Generate random host octets for the sample rules.
    readarray -t HOSTSa < <(shuf -i 1-254 -n 18)
    readarray -t HOSTSb < <(shuf -i 1-254 -n 18)

    # nft
    echo "limit_bandwidth $PREFIX.${HOSTSa[8]}.${HOSTSb[8]} 15mb 10s" >> "$BATCH_FILE"
    echo "LIMIT_BANDWIDTH $PREFIX.${HOSTSa[9]}.${HOSTSb[9]} 10mb" >> "$BATCH_FILE"
    echo "drop $PREFIX.${HOSTSa[0]}.${HOSTSb[0]}"   >> "$BATCH_FILE"
    echo "DROP $PREFIX.${HOSTSa[1]}.${HOSTSb[1]} 10s"   >> "$BATCH_FILE"
    echo "reject $PREFIX.${HOSTSa[2]}.${HOSTSb[2]} 10s"           >> "$BATCH_FILE"
    echo "REJECT $PREFIX.${HOSTSa[3]}.${HOSTSb[3]}" >> "$BATCH_FILE"
    echo "limit_concurrent $PREFIX.${HOSTSa[4]}.${HOSTSb[4]} 55 10s" >> "$BATCH_FILE"
    echo "LIMIT_CONCURRENT $PREFIX.${HOSTSa[5]}.${HOSTSb[5]} 50"   >> "$BATCH_FILE"
    echo "limit_conn_rate $PREFIX.${HOSTSa[6]}.${HOSTSb[6]} 25/second 10s"   >> "$BATCH_FILE"
    echo "LIMIT_CONN_RATE $PREFIX.${HOSTSa[7]}.${HOSTSb[7]} 20/second"           >> "$BATCH_FILE"
    
    #haproxy
    echo "timeout $PREFIX.${HOSTSa[10]}.${HOSTSb[10]} 5s 10s" >> "$BATCH_FILE"
    echo "TIMEOUT $PREFIX.${HOSTSa[11]}.${HOSTSb[11]} 10s"   >> "$BATCH_FILE"
    echo "limit_rate_slow $PREFIX.${HOSTSa[12]}.${HOSTSb[6]} 10s"   >> "$BATCH_FILE"
    echo "LIMIT_RATE_SLOW $PREFIX.${HOSTSa[13]}.${HOSTSb[7]}"           >> "$BATCH_FILE"
    echo "busy_deflection $PREFIX.${HOSTSa[14]}.${HOSTSb[14]} 10s" >> "$BATCH_FILE"
    echo "BUSY_DEFLECTION $PREFIX.${HOSTSa[15]}.${HOSTSb[15]}" >> "$BATCH_FILE"
    echo "limit_endpoint_rate $PREFIX.${HOSTSa[16]}.${HOSTSb[16]} 10/second /login,/api/export 10s" >> "$BATCH_FILE"
    echo "LIMIT_ENDPOINT_RATE $PREFIX.${HOSTSa[17]}.${HOSTSb[17]} 120/minute /search" >> "$BATCH_FILE"

done

echo "Generated $((LOOPS * 18)) test rules in $TMP_FILE:"
cat "$BATCH_FILE"

mv -f "$BATCH_FILE" "$TMP_FILE"
trap - EXIT
