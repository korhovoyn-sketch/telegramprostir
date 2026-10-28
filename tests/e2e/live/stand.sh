#!/usr/bin/env bash
# Піднімає ЖИВУ базу для браузерного проходу: shim Supabase + УСІ міграції по
# порядку (рівно як scripts/verify-migrations.sh), і лишає кластер працювати.
#   bash tests/e2e/live/stand.sh start   # кластер на unix-сокеті, база `live`
#   bash tests/e2e/live/stand.sh stop
# Параметри — змінні оточення LIVE_DATA / LIVE_SOCK / LIVE_PORT.
set -euo pipefail
PGBIN=${PGBIN:-/usr/lib/postgresql/16/bin}
export PATH="$PGBIN:$PATH"
DATA=${LIVE_DATA:-/tmp/pglive}
SOCK=${LIVE_SOCK:-/tmp/pglive-run}
PORT=${LIVE_PORT:-5434}
RUN=""
[ "$(id -u)" = "0" ] && RUN="su postgres -c"

ctl() { if [ -n "$RUN" ]; then $RUN "PATH=$PGBIN:\$PATH pg_ctl $*"; else pg_ctl "$@"; fi; }

if [ "${1:-start}" = "stop" ]; then
  ctl -D "$DATA" stop -m immediate >/dev/null 2>&1 || true
  exit 0
fi

ctl -D "$DATA" stop -m immediate >/dev/null 2>&1 || true
rm -rf "$DATA" "$SOCK"; mkdir -p "$DATA" "$SOCK"
if [ -n "$RUN" ]; then
  chown -R postgres:postgres "$DATA" "$SOCK"
  $RUN "PATH=$PGBIN:\$PATH initdb -D $DATA -U postgres --auth=trust" >/dev/null
  $RUN "PATH=$PGBIN:\$PATH pg_ctl -D $DATA -o '-p $PORT -k $SOCK -c listen_addresses=' -l $SOCK/pg.log start" >/dev/null
else
  initdb -D "$DATA" -U postgres --auth=trust >/dev/null
  pg_ctl -D "$DATA" -o "-p $PORT -k $SOCK -c listen_addresses=" -l "$SOCK/pg.log" start >/dev/null
fi
for _ in $(seq 1 60); do pg_isready -h "$SOCK" -p "$PORT" -U postgres >/dev/null 2>&1 && break; sleep 1; done

PSQL="psql -h $SOCK -p $PORT -U postgres -v ON_ERROR_STOP=1 -q"
psql -h "$SOCK" -p "$PORT" -U postgres -q -c "CREATE DATABASE live" >/dev/null
$PSQL -d live -f scripts/pg-shim.sql >/dev/null 2>&1
for f in $(ls supabase/migrations/*.sql | sort); do
  case "$(basename "$f")" in 0041_*|009_*) continue;; esac
  if ! out=$($PSQL -d live -f "$f" 2>&1); then
    echo "✗ $(basename "$f")"; echo "$out" | grep -E "ERROR" | head -3; exit 1
  fi
done
echo "✓ жива база: $(ls supabase/migrations/*.sql | wc -l) міграцій, сокет $SOCK:$PORT"
