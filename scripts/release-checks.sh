#!/usr/bin/env bash
# Друкує кількість пунктів у supabase/verify_release.sql — ОДНЕ джерело для
# build-release-sql.sh і verify-migrations.sh.
#
# Рахує не рядки за форматуванням, а НОМЕРИ пунктів `(N, '…'`, і вимагає, щоб
# вони складали рівно 1..N без пропусків і повторів (порядок у файлі
# довільний — таблицю впорядковує `ORDER BY ord`). Пункт, записаний інакше
# (перенесений рядок, зайвий пробіл), дає дірку в нумерації і падіння тут, а
# не тихо неправильне число, з яким потім звіряють вивід.
set -euo pipefail
file="${1:-supabase/verify_release.sql}"
ids=$(grep -oE "^[[:space:]]*\([0-9]+,[[:space:]]*'" "$file" | grep -oE '[0-9]+' || true)
n=$(printf '%s\n' "$ids" | grep -c . || true)
expected=$(seq 1 "$n" | tr '\n' ' ')
actual=$(printf '%s\n' "$ids" | sort -n | tr '\n' ' ')
if [ "$n" = "0" ] || [ "$expected" != "$actual" ]; then
  echo "✗ $file: номери пунктів не складають 1..N — знайдено: $actual" >&2
  exit 1
fi
echo "$n"
