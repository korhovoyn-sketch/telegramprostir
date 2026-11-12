#!/usr/bin/env bash
# Чи існує БЕЗПЕЧНИЙ (немажорний) фікс, якого ми ще не взяли.
#
# Чому не досить поля `fixAvailable: true` у `npm audit --json`: воно — ОЦІНКА
# npm, а не результат. Листопад 2026: `minimatch` має advisory лише для 10.x
# (фікс — 11.0.1), а `@typescript-eslint/typescript-estree` навіть в
# останній 8.72.1 вимагає `^10`. npm при цьому звітує `fixAvailable: true` для
# п'яти пакетів typescript-eslint, а `npm audit fix` лише ганяє парсер
# 8.59→8.72, тягне другу копію дерева і НЕ закриває жодного advisory. Крок, що
# вірить полю, стояв би червоним, доки typescript-eslint не підніме залежність,
# і привчив би ігнорувати себе.
#
# Тому питаємо РЕЗУЛЬТАТ: застосувати `npm audit fix` до копії lockfile і
# порівняти, які advisory зникли. Падаємо лише на тих, що фікс справді закрив.
set -euo pipefail

work=$(mktemp -d)
trap 'cp "$work/lock" package-lock.json; rm -rf "$work"' EXIT
cp package-lock.json "$work/lock"

ids() {
  npm audit --json 2>/dev/null | node -e '
    const a = JSON.parse(require("fs").readFileSync(0, "utf8"));
    for (const [k, v] of Object.entries(a.vulnerabilities ?? {}))
      for (const s of v.via) if (typeof s === "object") console.log(`${s.source}\t${v.severity}\t${k}\t${s.title}`);
  ' | sort -u || true
}

ids > "$work/before"
npm audit fix --package-lock-only --ignore-scripts >/dev/null 2>&1 || true
ids > "$work/after"

closed=$(awk -F'\t' 'NR==FNR { left[$1]=1; next } !($1 in left)' "$work/after" "$work/before")
if [ -z "$closed" ]; then
  echo "✓ npm audit fix (без --force) не закриває жодного advisory — решта обґрунтована в dependency-surface.test.ts"
  exit 0
fi
echo "::error::Зʼявився безпечний фікс — \`npm audit fix\` (без --force) закриє:"
printf '%s\n' "$closed" | awk -F'\t' '{printf "  %-8s %s — %s\n", $2, $3, $4}'
exit 1
