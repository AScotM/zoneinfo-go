#!/bin/bash
set -u

emit() {
  printf '%s=%s\n' "$1" "$2"
}

boolify() {
  case "${1:-}" in
    yes|true|1) printf 'true' ;;
    no|false|0) printf 'false' ;;
    *) printf 'unknown' ;;
  esac
}

sha256_of_file() {
  if [ -f "$1" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$1" | awk '{print $1}'
      return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
      openssl dgst -sha256 "$1" | awk '{print $NF}'
      return 0
    fi
  fi
  printf ''
}

os_pretty_name=''
if [ -r /etc/os-release ]; then
  os_pretty_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/^"/, "", $2); gsub(/"$/, "", $2); print $2}' /etc/os-release 2>/dev/null)
fi

hostname_short=$(hostname 2>/dev/null || printf '')
hostname_fqdn=$(hostname -f 2>/dev/null || printf '')
kernel=$(uname -srmo 2>/dev/null || printf '')
go_version=$(go version 2>/dev/null | awk '{print $3}')
if [ -z "$go_version" ]; then
  go_version=''
fi

timedatectl_available=false
timezone=''
ntp_enabled='unknown'
ntp_synced='unknown'
local_rtc='unknown'

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl_available=true
  while IFS='=' read -r key value; do
    case "$key" in
      Timezone) timezone="$value" ;;
      NTP) ntp_enabled=$(boolify "$value") ;;
      NTPSynchronized) ntp_synced=$(boolify "$value") ;;
      LocalRTC) local_rtc=$(boolify "$value") ;;
    esac
  done < <(timedatectl show --property=Timezone --property=NTP --property=NTPSynchronized --property=LocalRTC 2>/dev/null)
fi

if [ -z "$timezone" ] && [ -r /etc/timezone ]; then
  timezone=$(head -n1 /etc/timezone 2>/dev/null)
fi

localtime_path=$(readlink -f /etc/localtime 2>/dev/null || printf '')
localtime_hash=$(sha256_of_file /etc/localtime)
zoneinfo_path=''
zoneinfo_hash=''

if [ -n "$timezone" ] && [ -f "/usr/share/zoneinfo/$timezone" ]; then
  zoneinfo_path="/usr/share/zoneinfo/$timezone"
  zoneinfo_hash=$(sha256_of_file "$zoneinfo_path")
fi

now_iso=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || printf '')
now_epoch=$(date '+%s' 2>/dev/null || printf '')
utc_offset=$(date '+%z' 2>/dev/null || printf '')
tz_abbrev=$(date '+%Z' 2>/dev/null || printf '')

emit host_probe_version 1
emit hostname "$hostname_short"
emit fqdn "$hostname_fqdn"
emit os_pretty_name "$os_pretty_name"
emit kernel "$kernel"
emit go_version "$go_version"
emit timedatectl_available "$timedatectl_available"
emit timezone "$timezone"
emit ntp_service_active "$ntp_enabled"
emit ntp_synchronized "$ntp_synced"
emit local_rtc "$local_rtc"
emit localtime_path "$localtime_path"
emit localtime_sha256 "$localtime_hash"
emit zoneinfo_path "$zoneinfo_path"
emit zoneinfo_sha256 "$zoneinfo_hash"
emit now_iso "$now_iso"
emit now_epoch "$now_epoch"
emit utc_offset "$utc_offset"
emit tz_abbrev "$tz_abbrev"
