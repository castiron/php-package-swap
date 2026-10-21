#!/usr/bin/env bash
#
# php-esm-migrate.sh
#
# Response to CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") for Ubuntu hosts running
# PHP-FPM from the ondrej/php PPA (deb.sury.org):
#     Ubuntu 18.04 + PHP 7.2      Ubuntu 20.04 + PHP 7.4
#
#   1. Disables the Puppet agent (and waits out any run in progress) so nothing
#      reverts these changes mid-flight.
#   2. Backs up /etc/php/<version>, apt sources, and repacks the installed PPA packages as .debs.
#   3. Applies the interim FPM config mitigations from the PHP advisories.
#   4. Moves every PPA package to Ubuntu's ESM-maintained build of the same PHP version,
#      so Canonical's fix arrives through `apt upgrade`. PPA packages for another PHP
#      version that has no CLI/FPM installed (e.g. php8.2-common pulled in by the PPA's
#      php-mysql metapackage) are removed; they can't be run anyway.
#   5. Verifies the result.
#
# A host whose PHP-FPM isn't the PHP Ubuntu ships for that release (e.g. PHP 7.3 on
# 20.04) can't be migrated by this script, because that's a PHP upgrade. Run it with
# --skip-migrate to apply the config mitigations only.
#
# Usage:
#   sudo ./php-esm-migrate.sh            # dry run: checks and shows the plan, changes nothing
#   sudo ./php-esm-migrate.sh --apply    # do it
#
# Options:
#   --apply            make changes (default is a dry run)
#   --yes              skip confirmation prompts (with --apply)
#   --post-max SIZE    upper bound for post_max_size (default 32M; never raises the current value)
#   --memcap SIZE      systemd MemoryLimit for PHP-FPM (default: 75% of RAM)
#   --max-requests-1   set pm.max_requests = 1 in every pool (strong mitigation for
#                      CVE-2026-109619; costs CPU because every request gets a fresh worker)
#   --skip-mitigate    skip the interim mitigations; only turn off session.upload_progress
#                      (the advisory recommends keeping that off even after patching)
#   --skip-migrate     don't touch packages (config mitigations only)
#
# Puppet is left DISABLED at the end on purpose. Update your Puppet code (no ondrej
# PPA, Ubuntu PHP packages, these ini/pool settings) before `puppet agent --enable`.

set -Eeuo pipefail

# ---------------------------------------------------------------- arguments
APPLY=0 YES=0 POST_MAX=32M MEMCAP="" MAXREQ1=0 DO_MIGRATE=1 DO_MITIGATE=1
usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }
while (( $# )); do
  case "$1" in
    --apply)          APPLY=1 ;;
    --yes)            YES=1 ;;
    --post-max)       POST_MAX=${2:?--post-max needs a size}; shift ;;
    --memcap)         MEMCAP=${2:?--memcap needs a size}; shift ;;
    --max-requests-1) MAXREQ1=1 ;;
    --skip-mitigate)  DO_MITIGATE=0 ;;
    --skip-migrate)   DO_MIGRATE=0 ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
[[ $POST_MAX =~ ^[0-9]+[KMGkmg]?$ ]] || { echo "Bad --post-max: $POST_MAX" >&2; exit 2; }
[[ -z $MEMCAP || $MEMCAP =~ ^[0-9]+[KMGTkmgt]?$ ]] || { echo "Bad --memcap: $MEMCAP" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }

# ---------------------------------------------------------------- logging / helpers
TS=$(date +%Y%m%d-%H%M%S)
WORKDIR=/root/php-esm-migrate-$TS
mkdir -p "$WORKDIR/new"
exec > >(tee -a "$WORKDIR/run.log") 2>&1

WARNINGS=() INSTALL=() REMOVE=() REMOVE_ARGS=() LEFTOVER=() PROBLEMS=() PPA_LISTS=() PPA_SAVES=()
SL_HIT=0 PHPV="" FPMV="" FPM_BIN="" FPM_SVC="" ETC_PHP="" POOL_DIR=""
c_b=$'\e[1;34m' c_g=$'\e[32m' c_y=$'\e[33m' c_r=$'\e[1;31m' c_0=$'\e[0m'
step() { printf '\n%s==> %s%s\n' "$c_b" "$*" "$c_0"; }
ok()   { printf '    %sOK%s    %s\n' "$c_g" "$c_0" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '    %sWARN%s  %s\n' "$c_y" "$c_0" "$*"; WARNINGS+=("$*"); }
die()  { printf '\n%sABORT:%s %s\n' "$c_r" "$c_0" "$*"; printf 'Log and backups: %s\n' "$WORKDIR"; exit 1; }
trap 'die "unexpected error on line $LINENO (exit $?)"' ERR

confirm() {   # returns 0 if confirmed
  if (( YES )); then return 0; fi
  local ans=""
  read -r -p "    $1 Type 'yes' to continue: " ans </dev/tty || ans=""
  [[ $ans == yes ]]
}

to_bytes() {  # PHP shorthand size -> bytes; 0/empty/garbage = unlimited
  local v=${1^^}; v=${v// /}
  local big=9223372036854775807
  if [[ -z $v || $v == 0 ]]; then echo "$big"; return; fi
  local n=${v%[KMG]}
  if ! [[ $n =~ ^[0-9]+$ ]]; then echo "$big"; return; fi
  case $v in
    *K) echo $(( n << 10 )) ;;
    *M) echo $(( n << 20 )) ;;
    *G) echo $(( n << 30 )) ;;
    *)  echo "$n" ;;
  esac
}

smallest() {  # smallest PHP size among the arguments (empty args ignored)
  local best="" v
  for v in "$@"; do
    [[ -z $v ]] && continue
    if [[ -z $best ]] || (( $(to_bytes "$v") < $(to_bytes "$best") )); then best=$v; fi
  done
  printf '%s' "$best"
}

fpm_ini() {   # effective php.ini value for the FPM SAPI (ignores pool overrides)
  "$FPM_BIN" -i 2>/dev/null | awk -F' => ' -v k="$1" '$1==k && !s {print $2; s=1}' || true
}

pool_vals() { # values set for an ini key in pool files
  grep -hsE "^[[:space:]]*php(_admin)?_value\[$1\]" "$POOL_DIR"/*.conf \
    | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*(;.*)?$//' || true
}

installed() { dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii'; }

sury_packages() {
  dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' \
    | awk '$1=="ii" && $3 ~ /deb\.sury\.org/ {print $2}'
}

has_sapi() {  # is any way to run PHP version $1 installed?
  local s
  for s in "php$1-cli" "php$1-fpm" "php$1-cgi" "php$1-phpdbg" "libapache2-mod-php$1"; do
    if installed "$s"; then return 0; fi
  done
  return 1
}

best_ubuntu_version() {  # highest non-Sury version apt knows for a package
  local best="" v
  while IFS= read -r v; do
    [[ -z $v || $v == *sury* ]] && continue
    if [[ -z $best ]] || dpkg --compare-versions "$v" gt "$best"; then best=$v; fi
  done < <(apt-cache madison "$1" 2>/dev/null | awk -F'|' '$3 ~ /Packages/ {gsub(/[[:space:]]/, "", $2); print $2}')
  printf '%s' "$best"
}

wait_for_apt() {
  command -v fuser >/dev/null || return 0
  local i=0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if (( i == 0 )); then
      note "waiting (up to 10 min) for another apt/dpkg process to finish:"
      ps -o pid=,etime=,args= -p "$(fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock 2>/dev/null | xargs | tr ' ' ,)" 2>/dev/null \
        | sed 's/^/      /' || true
    fi
    i=$(( i + 1 ))
    if (( i > 120 )); then die "apt/dpkg lock still held after 10 minutes."; fi
    sleep 5
  done
}

restore_ppa() {
  local f
  for f in "${PPA_LISTS[@]}"; do
    [[ -f "$f.$TS.disabled" ]] && mv "$f.$TS.disabled" "$f"
  done
  if (( SL_HIT )); then sed -i "s|^# disabled by php-esm-migrate $TS: ||" /etc/apt/sources.list; fi
  wait_for_apt; apt-get update -qq || true
  note "PPA sources restored."
}

MODE=DRY-RUN; if (( APPLY )); then MODE=APPLY; fi
printf 'php-esm-migrate.sh   mode: %s   log: %s\n' "$MODE" "$WORKDIR/run.log"

# ================================================================ 1. Puppet
step "Step 1: Make sure Puppet can't run"
PUPPET=""
for c in /opt/puppetlabs/bin/puppet "$(command -v puppet 2>/dev/null || true)"; do
  if [[ -n $c && -x $c ]]; then PUPPET=$c; break; fi
done

if [[ -z $PUPPET ]]; then
  ok "Puppet is not installed"
else
  LOCK=$("$PUPPET" agent --configprint agent_disabled_lockfile 2>/dev/null) \
    || die "Puppet is installed but '$PUPPET agent --configprint' failed; disable it manually first."
  RUNLOCK=$("$PUPPET" agent --configprint agent_catalog_run_lockfile 2>/dev/null || true)

  if [[ -f $LOCK ]]; then
    ok "Puppet agent already disabled: $(cat "$LOCK" 2>/dev/null)"
  elif (( APPLY )); then
    "$PUPPET" agent --disable "CVE-2026-109618/109619: PHP PPA->Ubuntu ESM migration $TS by ${SUDO_USER:-root}"
    [[ -f $LOCK ]] || die "puppet agent --disable did not create $LOCK"
    ok "Puppet agent disabled ($LOCK)"
  else
    note "(dry-run) would run: $PUPPET agent --disable \"CVE-2026-109618/109619 ...\""
  fi

  if [[ -n $RUNLOCK && -f $RUNLOCK ]]; then
    PID=$(cat "$RUNLOCK" 2>/dev/null || true)
    if [[ -n $PID ]] && kill -0 "$PID" 2>/dev/null; then
      if (( APPLY )); then
        note "waiting for the in-progress Puppet run (pid $PID) to finish..."
        for _ in $(seq 1 120); do kill -0 "$PID" 2>/dev/null || break; sleep 5; done
        if kill -0 "$PID" 2>/dev/null; then die "Puppet run (pid $PID) still going after 10 minutes."; fi
        ok "In-progress Puppet run finished"
      else
        warn "A Puppet run is in progress right now (pid $PID)"
      fi
    fi
  fi

  # The agent lock does not stop `puppet apply` from cron or timers.
  APPLY_JOBS=$(grep -rlsE 'puppet[^#]*[[:space:]]apply' /etc/crontab /etc/cron.d /etc/cron.hourly \
                 /etc/cron.daily /var/spool/cron/crontabs /etc/systemd/system 2>/dev/null || true)
  if [[ -n $APPLY_JOBS ]]; then
    if (( APPLY )); then
      die "'puppet apply' is scheduled here and ignores 'puppet agent --disable'. Disable these first: $APPLY_JOBS"
    fi
    warn "'puppet apply' is scheduled and ignores the agent lock; disable before --apply: $APPLY_JOBS"
  else
    ok "No scheduled 'puppet apply' jobs found"
  fi
fi

# ================================================================ preflight
step "Preflight"
# shellcheck disable=SC1091
. /etc/os-release
case ${VERSION_ID:-} in
  18.04) PHPV=7.2 ;;
  20.04) PHPV=7.4 ;;
  *) die "Supported: Ubuntu 18.04 (PHP 7.2) and 20.04 (PHP 7.4); found ${PRETTY_NAME:-unknown}." ;;
esac
ok "$PRETTY_NAME (Ubuntu's own PHP for this release is $PHPV)"

mapfile -t FPM_VERS < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*-fpm' 2>/dev/null \
                          | awk '$1=="ii" {print $2}' | sed -nE 's/^php([0-9]+\.[0-9]+)-fpm$/\1/p')
(( ${#FPM_VERS[@]} )) || die "No phpX.Y-fpm package is installed."
for v in "${FPM_VERS[@]}"; do
  if [[ $v == "$PHPV" ]]; then FPMV=$v; fi
done
if [[ -z $FPMV ]]; then
  if (( ${#FPM_VERS[@]} > 1 )); then
    die "Several PHP-FPM versions are installed (${FPM_VERS[*]}) and none is $PHPV; handle this host manually."
  fi
  FPMV=${FPM_VERS[0]}
  if (( DO_MIGRATE )); then
    die "This host runs PHP-FPM $FPMV, but Ubuntu $VERSION_ID only packages PHP $PHPV, so leaving the PPA means upgrading PHP, which this script doesn't do. Rerun with --skip-migrate to apply the config mitigations only."
  fi
  warn "PHP-FPM $FPMV is not Ubuntu's PHP for this release: config mitigations only, and no fix will come from Ubuntu for it."
elif (( ${#FPM_VERS[@]} > 1 )); then
  warn "Other PHP-FPM versions are installed too (${FPM_VERS[*]}); only PHP $FPMV is handled."
fi
FPM_BIN=php-fpm$FPMV FPM_SVC=php$FPMV-fpm ETC_PHP=/etc/php/$FPMV POOL_DIR=/etc/php/$FPMV/fpm/pool.d
command -v "$FPM_BIN" >/dev/null || die "$FPM_BIN binary not found."
ok "php$FPMV-fpm $(dpkg-query -W -f='${Version}' "php$FPMV-fpm")"
if installed "libapache2-mod-php$FPMV"; then
  warn "libapache2-mod-php$FPMV is installed: mod_php is the highest-risk setup and this script only hardens FPM."
fi

PRO=$(command -v pro || command -v ua || true)
PRO_STATUS=""
if [[ -n $PRO ]]; then PRO_STATUS=$("$PRO" status 2>/dev/null || true); fi
if grep -Eq '^esm-infra +yes +enabled' <<<"$PRO_STATUS"; then
  ok "Ubuntu Pro esm-infra enabled"
elif (( DO_MIGRATE )); then
  die "Ubuntu Pro esm-infra is not enabled (check 'pro status'); without it Ubuntu's PHP $PHPV gets no fixes."
else
  warn "Ubuntu Pro esm-infra is not enabled"
fi

HELD=$(apt-mark showhold 2>/dev/null | grep -E '^(php|libapache2-mod-php)' || true)
[[ -z $HELD ]] || die "These packages are on hold; run 'apt-mark unhold' on them first: $(echo "$HELD" | tr '\n' ' ')"

"$FPM_BIN" -m > "$WORKDIR/modules-before.txt" 2>/dev/null || true

if (( APPLY )); then
  note "Rolling back the package switch means restoring a snapshot (the repacked .debs saved here are a backup)."
  confirm "Have you taken a snapshot of this server?" || die "Take a snapshot first, then rerun."
fi

# ================================================================ 2. Backups
step "Step 2: Backups -> $WORKDIR"
if (( APPLY )); then
  tar -czf "$WORKDIR/etc-php-$FPMV.tgz" -C / "etc/php/$FPMV"
  tar -czf "$WORKDIR/etc-apt.tgz" -C / etc/apt/sources.list etc/apt/sources.list.d
  if [[ -d /etc/systemd/system/$FPM_SVC.service.d ]]; then
    tar -czf "$WORKDIR/fpm-systemd-dropins.tgz" -C / "etc/systemd/system/$FPM_SVC.service.d"
  fi
  dpkg-query -W -f='${db:Status-Abbrev} ${Package}=${Version}\n' | awk '$1=="ii" {print $2}' \
    > "$WORKDIR/package-versions.txt"
  ok "Config, apt sources and package list saved"

  mapfile -t SURY_NOW < <(sury_packages)
  if (( DO_MIGRATE )) && (( ${#SURY_NOW[@]} )); then
    if ! command -v dpkg-repack >/dev/null; then
      wait_for_apt
      apt-get install -y -qq dpkg-repack >/dev/null 2>&1 || warn "Could not install dpkg-repack; no .deb backup (snapshot is your rollback)"
    fi
    if command -v dpkg-repack >/dev/null; then
      mkdir -p "$WORKDIR/debs"
      ( cd "$WORKDIR/debs" && for p in "${SURY_NOW[@]}"; do
          dpkg-repack "$p" >/dev/null 2>&1 || echo "    could not repack $p"
        done )
      ok "Repacked $(find "$WORKDIR/debs" -name '*.deb' | wc -l) of ${#SURY_NOW[@]} PPA packages into $WORKDIR/debs"
    fi
  fi
else
  note "(dry-run) would back up $ETC_PHP, apt sources, the package list, and repack the PPA packages"
fi

# ================================================================ 3. Mitigations
step "Step 3: FPM config mitigations"
FULL_MARK='CVE-2026-109618/109619 mitigation'
UP_MARK='session upload progress off'
SYSTEMD_DROPIN=/etc/systemd/system/$FPM_SVC.service.d/zz-cve-2026-109618.conf
if (( DO_MITIGATE )); then
  MARK=$FULL_MARK
  DROPIN_INI=$ETC_PHP/fpm/conf.d/99-cve-2026-109618-109619.ini
else
  # Even without the interim mitigations, session upload progress is turned off:
  # it's one of the confirmed exploit paths, and the advisory recommends keeping
  # it off after patching too.
  MARK=$UP_MARK
  DROPIN_INI=$ETC_PHP/fpm/conf.d/99-session-upload-progress-off.ini
  note "--skip-mitigate: only turning off session.upload_progress (keep it off even after patching)"
fi

{
  shopt -s nullglob
  POOLS=("$POOL_DIR"/*.conf)
  shopt -u nullglob
  (( ${#POOLS[@]} )) || die "No pool files found in $POOL_DIR"

  if (( ! DO_MITIGATE )); then
  note "session.upload_progress.enabled  $(fpm_ini session.upload_progress.enabled) -> 0"
  if (( MAXREQ1 )); then note "pm.max_requests                  -> 1 (every pool)"; fi
  cat > "$WORKDIR/new/dropin.ini" <<EOF
; $MARK, added by php-esm-migrate.sh on $TS (CVE-2026-109619).
; Keep this even after patching, as the PHP advisory recommends.
session.upload_progress.enabled = 0
EOF
  POOL_BLOCK="; >>> $MARK (php-esm-migrate.sh $TS)
php_admin_flag[session.upload_progress.enabled] = off"
  KEYS='session\.upload_progress\.enabled'
  else

  # Work out targets: never raise an existing limit.
  mapfile -t PV < <(pool_vals post_max_size)
  mapfile -t UV < <(pool_vals upload_max_filesize)
  CUR_POST=$(smallest "$(fpm_ini post_max_size)" "${PV[@]}")
  TARGET_POST=$(smallest "$CUR_POST" "$POST_MAX")
  POST_B=$(to_bytes "$TARGET_POST")
  CUR_UP=$(smallest "$(fpm_ini upload_max_filesize)" "${UV[@]}")
  if [[ -n $CUR_UP ]] && (( $(to_bytes "$CUR_UP") < POST_B )); then
    TARGET_UP=$CUR_UP
  elif (( POST_B >= (2 << 20) )); then
    TARGET_UP="$(( (POST_B >> 20) - 1 ))M"      # just under post_max_size, e.g. 30M -> 29M
  else
    TARGET_UP="$(( POST_B * 7 / 8 / 1024 ))K"
  fi
  CUR_NEST=$(fpm_ini max_input_nesting_level)
  [[ $CUR_NEST =~ ^[0-9]+$ ]] || CUR_NEST=64
  TARGET_NEST=$(( CUR_NEST < 32 ? CUR_NEST : 32 ))

  note "memory_limit                     $(fpm_ini memory_limit) -> -1 (capped by systemd instead)"
  note "post_max_size                    ${CUR_POST:-?} -> $TARGET_POST"
  note "upload_max_filesize              ${CUR_UP:-?} -> $TARGET_UP"
  note "max_input_nesting_level          $CUR_NEST -> $TARGET_NEST"
  note "session.upload_progress.enabled  $(fpm_ini session.upload_progress.enabled) -> 0"
  if (( MAXREQ1 )); then note "pm.max_requests                  -> 1 (every pool)"; fi
  note "(If the site needs uploads bigger than $TARGET_UP, raise it with --post-max; the advisory suggests <= 32M.)"

  # php.ini drop-in (startup config, applies before any request)
  cat > "$WORKDIR/new/dropin.ini" <<EOF
; $MARK, added by php-esm-migrate.sh on $TS.
; Interim hardening until Ubuntu's fixed PHP is installed.
; Keep session.upload_progress.enabled = 0 even after patching.
memory_limit = -1
post_max_size = $TARGET_POST
upload_max_filesize = $TARGET_UP
max_input_nesting_level = $TARGET_NEST
session.upload_progress.enabled = 0
EOF

  # Pool block: php_admin_* so applications can't ini_set() a finite memory_limit back.
  POOL_BLOCK="; >>> $MARK (php-esm-migrate.sh $TS)
php_admin_value[memory_limit] = -1
php_admin_value[post_max_size] = $TARGET_POST
php_admin_value[upload_max_filesize] = $TARGET_UP
php_admin_value[max_input_nesting_level] = $TARGET_NEST
php_admin_flag[session.upload_progress.enabled] = off"
  KEYS='memory_limit|post_max_size|upload_max_filesize|max_input_nesting_level|session\.upload_progress\.enabled'
  fi
  if (( MAXREQ1 )); then POOL_BLOCK+=$'\npm.max_requests = 1'; fi
  POOL_BLOCK+=$'\n; <<< '"$MARK"
  export POOL_BLOCK

  for f in "${POOLS[@]}"; do
    out="$WORKDIR/new/pool-$(basename "$f")"
    if grep -qF "$MARK" "$f" || { (( ! DO_MITIGATE )) && grep -qF "$FULL_MARK" "$f"; }; then
      note "$(basename "$f"): mitigation block already present, leaving as is"
      cp "$f" "$out"; continue
    fi
    # Comment out existing settings for the same keys (a later line would win over ours).
    sed -E "s/^([[:space:]]*php(_admin)?_(value|flag)\[($KEYS)\].*)$/;[disabled by php-esm-migrate $TS] \1/" "$f" > "$out.tmp"
    if (( MAXREQ1 )); then
      sed -i -E "s/^([[:space:]]*pm\.max_requests[[:space:]]*=.*)$/;[disabled by php-esm-migrate $TS] \1/" "$out.tmp"
    fi
    # Insert our block right after every [pool] header.
    awk '{print} /^[[:space:]]*\[.+\][[:space:]]*$/ && !/\[global\]/ {print ENVIRON["POOL_BLOCK"]}' "$out.tmp" > "$out"
    rm -f "$out.tmp"
    grep -qF "$MARK" "$out" || die "$(basename "$f"): no [pool] section header found"
    note "Changes to $f:"
    diff -u "$f" "$out" | sed 's/^/      /' || true
  done

  # systemd: replace PHP's per-request memory cap with a service-level one.
  if (( DO_MITIGATE )); then
  if [[ -z $MEMCAP ]]; then
    MEMCAP="$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) * 3 / 4 / 1024 ))M"
  fi
  cat > "$WORKDIR/new/systemd.conf" <<EOF
# $MARK, added by php-esm-migrate.sh on $TS.
# memory_limit is -1, so cap the whole service instead.
# Never use LimitAS/LimitDATA here: they make allocations fail, which is the vulnerable path.
[Service]
MemoryAccounting=yes
MemoryLimit=$MEMCAP
LimitAS=infinity
LimitDATA=infinity
Restart=on-failure
EOF
  note "systemd MemoryLimit for $FPM_SVC: $MEMCAP"
  fi

  PVAL=$(grep -rnsE 'PHP_(ADMIN_)?VALUE' /etc/nginx /etc/apache2 2>/dev/null || true)
  if [[ -z $PVAL ]]; then
    ok "Web server does not pass per-request PHP_VALUE/PHP_ADMIN_VALUE"
  else
    warn "Web server passes per-request PHP settings; remove invalid/deprecated ones, prefer pool config:"
    printf '%s\n' "$PVAL" | sed 's/^/      /'
  fi

  if (( APPLY )); then
    SYSTEMD_HAD=0; [[ -e $SYSTEMD_DROPIN ]] && SYSTEMD_HAD=1
    install -m 0644 "$WORKDIR/new/dropin.ini" "$DROPIN_INI"
    for f in "${POOLS[@]}"; do cat "$WORKDIR/new/pool-$(basename "$f")" > "$f"; done
    if (( DO_MITIGATE )); then
      mkdir -p "$(dirname "$SYSTEMD_DROPIN")"
      install -m 0644 "$WORKDIR/new/systemd.conf" "$SYSTEMD_DROPIN"
    fi
    if ! "$FPM_BIN" -t >"$WORKDIR/fpm-test.txt" 2>&1; then
      sed 's/^/      /' "$WORKDIR/fpm-test.txt"
      rm -f "$DROPIN_INI"
      if (( DO_MITIGATE && ! SYSTEMD_HAD )); then rm -f "$SYSTEMD_DROPIN"; fi
      tar -xzf "$WORKDIR/etc-php-$FPMV.tgz" -C /
      systemctl daemon-reload
      die "$FPM_BIN -t rejected the new config; original config restored."
    fi
    systemctl daemon-reload
    systemctl restart "$FPM_SVC"
    systemctl is-active --quiet "$FPM_SVC" || die "$FPM_SVC did not come back up (journalctl -u $FPM_SVC)."
    ok "Config changes in place, $FPM_SVC restarted"
  else
    if (( DO_MITIGATE )); then
      note "(dry-run) would write $DROPIN_INI, the pool changes above, $SYSTEMD_DROPIN, then test and restart $FPM_SVC"
    else
      note "(dry-run) would write $DROPIN_INI and the pool changes above, then test and restart $FPM_SVC"
    fi
  fi
}

# ================================================================ 4. Migration
step "Step 4: Move PHP $PHPV from the ondrej PPA to Ubuntu ESM packages"
if (( ! DO_MIGRATE )); then
  note "Skipped (--skip-migrate)"
else
  mapfile -t SURY < <(sury_packages)
  if (( ${#SURY[@]} == 0 )); then
    ok "No ondrej/Sury packages installed"
  else
    note "${#SURY[@]} packages installed from the PPA"

    # esm-apps covers universe (php-imagick and some php*-* binaries)
    if grep -Eq '^esm-apps +yes +enabled' <<<"$PRO_STATUS"; then
      ok "esm-apps enabled"
    elif grep -Eq '^esm-apps +yes' <<<"$PRO_STATUS"; then
      if (( APPLY )); then "$PRO" enable esm-apps --assume-yes; ok "esm-apps enabled"
      else note "(dry-run) would run: $PRO enable esm-apps"; fi
    else
      warn "esm-apps isn't available on this subscription; universe packages (php-imagick etc.) won't get ESM fixes"
    fi

    # Find the PPA in apt sources
    mapfile -t PPA_LISTS < <(grep -lsE '^[[:space:]]*deb[^#]*ondrej/php' /etc/apt/sources.list.d/*.list 2>/dev/null || true)
    mapfile -t PPA_SAVES < <(find /etc/apt/sources.list.d -maxdepth 1 -name '*ondrej*php*.save' 2>/dev/null)
    SL_HIT=$(grep -cE '^[[:space:]]*deb[^#]*ondrej/php' /etc/apt/sources.list 2>/dev/null || true)
    SL_HIT=${SL_HIT:-0}

    if (( APPLY )); then
      for f in "${PPA_LISTS[@]}"; do mv "$f" "$f.$TS.disabled"; note "disabled $f"; done
      for f in "${PPA_SAVES[@]}"; do mv "$f" "$WORKDIR/"; done
      if (( SL_HIT )); then
        sed -i -E "s|^([[:space:]]*deb[^#]*ondrej/php.*)$|# disabled by php-esm-migrate $TS: \1|" /etc/apt/sources.list
        note "commented out ondrej/php in /etc/apt/sources.list"
      fi
      wait_for_apt
      apt-get update -q
    else
      note "(dry-run) would disable PPA source(s): ${PPA_LISTS[*]:-none}${PPA_SAVES[*]:+ (and move ${PPA_SAVES[*]})}"
      note "(dry-run) plan below uses current apt lists; the real run disables the PPA first"
    fi

    note "Package mapping:"
    for p in "${SURY[@]}"; do
      if [[ $p =~ ^php([0-9]+\.[0-9]+)- ]]; then
        ov=${BASH_REMATCH[1]}
        if [[ $ov != "$PHPV" ]]; then
          if has_sapi "$ov"; then
            PROBLEMS+=("$p")
          else
            REMOVE+=("$p"); REMOVE_ARGS+=("$p-")
            note "  $p  ->  remove (no PHP $ov CLI/FPM installed, so nothing can run it)"
          fi
          continue
        fi
      fi
      v=$(best_ubuntu_version "$p")
      if [[ -n $v ]]; then
        INSTALL+=("$p=$v"); note "  $p  ->  $v"
      elif [[ $p == "php$PHPV-imagick" ]]; then
        iv=$(best_ubuntu_version php-imagick)
        [[ -n $iv ]] || die "php-imagick is not available from the Ubuntu repositories"
        REMOVE+=("$p"); REMOVE_ARGS+=("$p-"); INSTALL+=("php-imagick=$iv")
        note "  $p  ->  php-imagick=$iv (Ubuntu's name for it)"
      elif [[ $p == lib* ]]; then
        LEFTOVER+=("$p"); note "  $p  ->  no Ubuntu version; left installed (library, unused afterwards)"
      else
        PROBLEMS+=("$p")
      fi
    done
    if (( ${#PROBLEMS[@]} )); then
      if (( APPLY )); then restore_ppa; fi
      die "No Ubuntu replacement for: ${PROBLEMS[*]}. These belong to a PHP version that's in use, or have no Ubuntu package; handle them manually, then rerun."
    fi

    APT_OPTS=(-y -q --allow-downgrades -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    if ! SIM=$(apt-get install -s "${APT_OPTS[@]}" "${INSTALL[@]}" "${REMOVE_ARGS[@]}" 2>&1); then
      printf '%s\n' "$SIM" | tail -n 30 | sed 's/^/      /'
      if (( APPLY )); then restore_ppa; fi
      die "apt could not resolve the switch (simulation failed)."
    fi
    printf '%s\n' "$SIM" > "$WORKDIR/apt-simulation.txt"
    note "Planned apt changes (full output: $WORKDIR/apt-simulation.txt):"
    grep -E '^(Inst|Remv)' <<<"$SIM" | sed 's/^/      /' || true

    UNEXPECTED=$(awk '/^Remv /{print $2}' <<<"$SIM" | while read -r r; do
                   [[ " ${REMOVE[*]} " == *" $r "* ]] || echo "$r"; done)
    if [[ -n $UNEXPECTED ]]; then
      if (( APPLY )); then restore_ppa; fi
      die "apt wants to remove packages this script didn't plan to: $(echo "$UNEXPECTED" | tr '\n' ' ')"
    fi
    ok "No unexpected removals"

    if (( APPLY )); then
      if ! confirm "Proceed with the package changes above?"; then
        restore_ppa
        die "Package switch not confirmed. Config mitigations (if any) are still in place."
      fi
      wait_for_apt
      DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 \
        apt-get install "${APT_OPTS[@]}" "${INSTALL[@]}" "${REMOVE_ARGS[@]}"
      systemctl restart "$FPM_SVC"
      ok "Packages switched to Ubuntu ESM"
    else
      note "(dry-run) no packages changed"
    fi
  fi
fi

# ================================================================ 5. Verify
step "Step 5: Verify"
if (( APPLY )); then
  if systemctl is-active --quiet "$FPM_SVC"; then ok "$FPM_SVC is running"
  else warn "$FPM_SVC is NOT running (journalctl -u $FPM_SVC)"; fi
  ok "$("$FPM_BIN" -v 2>/dev/null | sed -n 1p)"

  if (( DO_MIGRATE )); then
    LEFT=$(sury_packages | grep -vxF -f <(printf '%s\n' "${LEFTOVER[@]:-}") || true)
    if [[ -z $LEFT ]]; then ok "No PPA PHP packages left"
    else warn "Still installed from the PPA: $(echo "$LEFT" | tr '\n' ' ')"; fi
    CV=$(dpkg-query -W -f='${Version}' "php$PHPV-common")
    if [[ $CV != *sury* ]]; then ok "php$PHPV-common $CV (Ubuntu ESM track)"
    else warn "php$PHPV-common is $CV, still the PPA build"; fi

    # Shared libraries (libpcre, libzip, ...) were swapped too; anything started before
    # the switch still has the old copy mapped until it restarts.
    STALE=$(grep -lsE '(libpcre|libzip|libicu|libargon2)[^ ]*\.so[^ ]* \(deleted\)' /proc/[0-9]*/maps 2>/dev/null \
              | cut -d/ -f3 | xargs -r ps -o comm= -p 2>/dev/null | sort -u | tr '\n' ' ' || true)
    if [[ -n $STALE ]]; then
      note "Processes still using the previous copy of a swapped library (harmless until they restart):"
      note "  $STALE"
      note "  Restart the web server now (systemctl restart nginx / apache2); reboot when convenient for the rest."
    else
      ok "No running process holds the replaced libraries"
    fi
  fi

  "$FPM_BIN" -m > "$WORKDIR/modules-after.txt" 2>/dev/null || true
  if diff -u "$WORKDIR/modules-before.txt" "$WORKDIR/modules-after.txt" > "$WORKDIR/modules.diff"; then
    ok "Same PHP modules loaded as before"
  else
    warn "Loaded PHP modules changed (see below)"
    sed 's/^/      /' "$WORKDIR/modules.diff"
  fi

  if (( DO_MITIGATE )); then
    note "Effective php.ini values (FPM):"
    for k in memory_limit post_max_size upload_max_filesize max_input_nesting_level session.upload_progress.enabled; do
      note "  $k = $(fpm_ini "$k")"
    done
    note "Pool overrides:"
    "$FPM_BIN" -tt 2>&1 | grep -E 'php_admin_(value|flag)|pm\.max_requests' | sed -E 's/^.*NOTICE:[[:space:]]*/      /' || true
    note "systemd: $(systemctl show "$FPM_SVC" -p MemoryLimit -p LimitAS -p LimitDATA | tr '\n' ' ')"
  else
    UPV=$(fpm_ini session.upload_progress.enabled)
    if [[ $UPV == Off || $UPV == 0 ]]; then ok "session.upload_progress.enabled = $UPV"
    else warn "session.upload_progress.enabled is still '$UPV'"; fi
  fi
else
  note "(dry-run) nothing to verify"
fi

# ================================================================ summary
trap - ERR
step "Done ($MODE)"
if (( ${#WARNINGS[@]} )); then
  note "Warnings:"
  for w in "${WARNINGS[@]}"; do note "  - $w"; done
fi

if (( ! APPLY )); then
  cat <<EOF

Dry run complete; nothing was changed. Review the plan above, take a snapshot,
then run:   sudo $0 --apply $( (( DO_MIGRATE )) || echo --skip-migrate )
Plan files: $WORKDIR
EOF
  exit 0
fi

cat <<EOF

Next:
  * Test the site now: logins, forms, uploads, image handling, database paths.
  * Puppet is still DISABLED. Before 'puppet agent --enable', update the Puppet code so it
    no longer adds the ondrej PPA or pins Sury versions, and carries these php.ini, pool
    and systemd settings. Otherwise the next run may undo all of this.
EOF
if (( DO_MIGRATE )); then
  cat <<EOF
  * When Ubuntu's fixed php$PHPV reaches the ESM repository, install it and restart FPM:
      apt-get update
      apt-get install --only-upgrade \$(dpkg-query -W -f='\${db:Status-Abbrev} \${Package}\n' 'php$PHPV-*' | awk '\$1=="ii"{print \$2}')
      systemctl restart $FPM_SVC
  * Rollback: restore the snapshot. Partial fallback:
      dpkg -i $WORKDIR/debs/*.deb && tar -xzf $WORKDIR/etc-php-$FPMV.tgz -C / && systemctl restart $FPM_SVC
EOF
else
  cat <<EOF
  * This host's PHP $FPMV gets no fix from Ubuntu; plan its move to Ubuntu's PHP $PHPV.
EOF
fi
printf '\nLog and backups: %s\n' "$WORKDIR"
