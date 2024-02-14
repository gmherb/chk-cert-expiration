#!/usr/bin/env bash

set -euxo pipefail

readonly NETWORK_CIDR=${1:-"192.168.0.0/23"}

readonly EXPIRATION_THRESHOLD=30
readonly EXPIRATION_DATE=$(date -d "+${EXPIRATION_THRESHOLD} days" +%s)
readonly PORT_RANGE="1-1024"

# nmap-formater is a go binary installed with:
# go install github.com/vdjagilev/nmap-formatter/v2@latest
PATH=$PATH:~/go/bin

nmap --version || {
  echo "nmap is not installed, please install nmap and try again ..."
  exit 1
}
jq --version || {
  echo "jq is not installed, please install jq and try again ..."
  exit 1
}
nmap-formatter --version || {
  echo "nmap-formatter is not installed, please install nmap-formatter and try again ..."
  exit 1
}

readonly NMAP_XML_OUTPUT=$(nmap -p ${PORT_RANGE} --open -n -T5 --script ssl-cert -oX - ${NETWORK_CIDR})
readonly NMAP_FORMATTED_OUTPUT=$(nmap-formatter json <<< "${NMAP_XML_OUTPUT}")

readonly HOST_COUNT=$(jq '.Host|length' <<< "${NMAP_FORMATTED_OUTPUT}")

EXPIRING_CERTS=()

for i in $(seq 0 $HOST_COUNT); do
  [[ $i -eq $HOST_COUNT ]] && break

  HOST=$(jq -r ".Host[$i].HostAddress[0].Address" <<< "${NMAP_FORMATTED_OUTPUT}")
  PORT_COUNT=$(jq ".Host[$i].Port|length" <<< "${NMAP_FORMATTED_OUTPUT}")
  echo "Checking [$PORT_COUNT] open ports on host [$HOST] ..."

  for p in $(seq 0 $PORT_COUNT); do
    [[ $p -eq $PORT_COUNT ]] && break

    PORT=$(jq -r ".Host[$i].Port[$p].PortID" <<< "${NMAP_FORMATTED_OUTPUT}")
    PROTOCOL=$(jq -r ".Host[$i].Port[$p].Protocol" <<< "${NMAP_FORMATTED_OUTPUT}")

    echo "Checking socket [${HOST}:${PORT}] ..."
    CERT_INFO=$(jq .Host[$i].Port[$p].Script[0].Output <<< "${NMAP_FORMATTED_OUTPUT}")

    [[ $CERT_INFO == null ]] && {
      echo "No certificate found for [${HOST}:${PORT}] ..."
      continue
    }

    CERT_NOT_AFTER=$(grep -m1 -o -e 'Not valid after: *[0-9-]*T[0-9:]*' <<< "${CERT_INFO}" | awk '{print $NF}')

    CERT_NOT_AFTER_EPOCH=$(date -d "${CERT_NOT_AFTER}" +%s)
    CERT_EXPIRATION_DAYS=$((($CERT_NOT_AFTER_EPOCH - $(date +%s)) / 86400))

    echo "Certificate at [${HOST}:${PORT}] expires in [${CERT_EXPIRATION_DAYS}] days ..."

    [[ $CERT_EXPIRATION_DAYS -lt $EXPIRATION_THRESHOLD ]] && EXPIRING_CERTS+=("${HOST}:${PORT}")


    COMMON_NAME=$(grep -oP 'commonName=\K[^/]+' <<< "${CERT_INFO}" | head -1)
    ORGANIZATION_NAME=$(grep -oP 'organizationName=\K[^/]+' <<< "${CERT_INFO}" | head -1)
    STATE_OR_PROVINCE_NAME=$(grep -oP 'stateOrProvinceName=\K[^/]+' <<< "${CERT_INFO}" | head -1)
    COUNTRY_NAME=$(grep -oP 'countryName=\K[^\\s]+' <<< "${CERT_INFO}" | head -1)
    SUBJECT_ALTERNATIVE_NAME=$(grep -oP 'Subject Alternative Name: \K[^\\s]+' <<< "${CERT_INFO}" | head -1)
    ISSUER=$(grep -oP 'Issuer: commonName=\K[^/]+' <<< "${CERT_INFO}" | head -1)
    
    jo -p \
      host="${HOST}" \
      port="${PORT}" \
      protocol="${PROTOCOL}" \
      common_name="${COMMON_NAME}" \
      organization_name="${ORGANIZATION_NAME}" \
      state_or_province_name="${STATE_OR_PROVINCE_NAME}" \
      country_name="${COUNTRY_NAME}" \
      subject_alternative_name="${SUBJECT_ALTERNATIVE_NAME}" \
      issuer="${ISSUER}" \
      not_after="${CERT_NOT_AFTER}" \
      expiration_days="${CERT_EXPIRATION_DAYS}"


  done
done

echo "Found [${#EXPIRING_CERTS[@]}] certificates in the [$NETWORK_CIDR] network which expire within [$EXPIRATION_THRESHOLD] days ..."
for c in "${EXPIRING_CERTS[@]}"; do
  echo "Expiring certificate: [$c] ..."
done