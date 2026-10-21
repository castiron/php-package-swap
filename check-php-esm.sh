#!/usr/bin/env bash
#
# check-php-esm.sh: quick yes/no check that this Ubuntu host will receive
# Ubuntu's PHP security fixes automatically.
#
#   1. PHP comes from Ubuntu's packages (not the ondrej/php PPA)
#   2. Ubuntu Pro Expanded Security Maintenance (esm-infra) is enabled
#   3. Unattended upgrades are on and allowed to install ESM updates
#
# Read-only; changes nothing. Exit status is 0 only if all three pass.
#
# Usage: ./check-php-esm.sh

set -uo pipefail

FAILS=0
line() {  # line PASS|FAIL "label" "detail"
  local mark=$1 label=$2 detail=${3:-}
  if [[ $mark == FAIL ]]; then FAILS=$((FAILS + 1)); fi
  printf '%-4s  %-32s %s\n' "$mark" "$label" "$detail"
}

# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
case ${VERSION_ID:-} in
  18.04) PHPV=7.2 ;;
  20.04) PHPV=7.4 ;;
  22.04) PHPV=8.1 ;;
  24.04) PHPV=8.3 ;;
  *)     PHPV=$(ls /etc/php 2>/dev/null | sort -V | tail -1) ;;
esac

# ---- 1. PHP from Ubuntu packages
LABEL1="PHP from Ubuntu packages"
SURY=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 2>/dev/null \
         | awk '$1=="ii" && $2 ~ /^(php|libapache2-mod-php)/ && $3 ~ /sury/ {print $2}' | xargs)
PPA=$(grep -lsE '^[[:space:]]*deb[^#]*ondrej/php' /etc/apt/sources.list /etc/apt/sources.list.d/*.list | xargs)
FPM=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*-fpm' 2>/dev/null \
        | awk '$1=="ii" {print $2, $3; exit}')
if [[ -z $FPM ]]; then
  FPM=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*-cli' 2>/dev/null \
          | awk '$1=="ii" {print $2, $3; exit}')
fi
if [[ -z $FPM ]]; then
  line FAIL "$LABEL1" "no PHP installed"
elif [[ -n $SURY ]]; then
  line FAIL "$LABEL1" "still from the ondrej PPA: $SURY"
elif [[ -n $PPA ]]; then
  line FAIL "$LABEL1" "$FPM, but the ondrej PPA is still enabled ($PPA)"
elif [[ ${FPM%% *} != php$PHPV-* ]]; then
  line FAIL "$LABEL1" "$FPM is not Ubuntu's PHP for this release (php$PHPV)"
else
  line PASS "$LABEL1" "$FPM"
fi

# ---- 2. Ubuntu Pro ESM
LABEL2="Ubuntu Pro ESM enabled"
PRO=$(command -v pro || command -v ua || true)
PRO_STATUS=""
if [[ -n $PRO ]]; then PRO_STATUS=$("$PRO" status 2>/dev/null || true); fi
ESM_ON=$(awk '$1 ~ /^esm-(infra|apps)$/ && $3=="enabled" {print $1}' <<<"$PRO_STATUS" | xargs)
if [[ -z $PRO ]]; then
  line FAIL "$LABEL2" "Ubuntu Pro client not installed"
elif [[ $ESM_ON != *esm-infra* ]]; then
  line FAIL "$LABEL2" "esm-infra is not enabled (attach with: pro attach <token>)"
elif ! apt-cache policy 2>/dev/null | grep -q 'esm.ubuntu.com/infra'; then
  line FAIL "$LABEL2" "esm-infra enabled but its apt source is missing (run: apt-get update)"
else
  line PASS "$LABEL2" "${ESM_ON// /, }"
fi

# ---- 3. Unattended upgrades
LABEL3="Unattended upgrades on"
APTCFG=$(apt-config dump 2>/dev/null)
# Config entries are often unexpanded ("${distro_id}ESM:..."), so also use the
# expanded list unattended-upgrade logged on its last run.
ORIGINS=$(grep -E '^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)::' <<<"$APTCFG"
          grep -h 'Allowed origins are:' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -1)
LAST=$(grep -h 'Starting unattended upgrades script' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null \
         | tail -1 | cut -c1-16)
if ! dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | grep -q '^ii'; then
  line FAIL "$LABEL3" "unattended-upgrades is not installed"
elif ! grep -q '^APT::Periodic::Unattended-Upgrade "1"' <<<"$APTCFG"; then
  line FAIL "$LABEL3" "turned off (APT::Periodic::Unattended-Upgrade is not \"1\")"
elif ! grep -q '^APT::Periodic::Update-Package-Lists "1"' <<<"$APTCFG"; then
  line FAIL "$LABEL3" "package lists aren't refreshed daily (APT::Periodic::Update-Package-Lists)"
elif ! systemctl is-enabled --quiet apt-daily.timer 2>/dev/null \
  || ! systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null; then
  line FAIL "$LABEL3" "apt-daily timers are disabled"
elif ! grep -qE 'ESM(Infra)?:|o=UbuntuESM[,"]|ESM,' <<<"$ORIGINS"; then
  line FAIL "$LABEL3" "on, but not allowed to install ESM updates (Allowed-Origins)"
elif grep -A50 '^Unattended-Upgrade::Package-Blacklist' <<<"$APTCFG" \
       | grep -E '^Unattended-Upgrade::Package-Blacklist::' | grep -qi 'php'; then
  line FAIL "$LABEL3" "on, but PHP is blacklisted (Unattended-Upgrade::Package-Blacklist)"
else
  line PASS "$LABEL3" "${LAST:+last run $LAST}"
fi

exit $(( FAILS > 0 ))
