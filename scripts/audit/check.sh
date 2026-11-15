#!/usr/bin/env bash
# Сохраняет полный вывод и исходный код выхода, даже если проверка не прошла.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/audit-out"
checks=(patches environment install-staticcheck install-golangci install-govulncheck
  race-config vet-config staticcheck-config
  race-rescuestats vet-rescuestats staticcheck-rescuestats
  race-hcore vet-hcore staticcheck-hcore race-rule race-monitoring
  golangci-lint govulncheck)
mkdir -p "$out"

case "${1:-}" in
  init)
    for name in "${checks[@]}"; do
      echo 'NOT RUN: prerequisite failed or job interrupted.' > "$out/$name.txt"
      echo 'NOT RUN' > "$out/$name.exit"
    done
    bash "$root/scripts/audit/check.sh" summary
    ;;
  run)
    name="$2"
    directory="$3"
    shift 3
    # Всего до 48 минут команд; остаётся время на Actions и выгрузку отчёта.
    case "$name" in
      patches|environment) limit=1m ;;
      install-staticcheck) limit=3m ;;
      install-golangci) limit=5m ;;
      install-govulncheck) limit=2m ;;
      race-*) limit=4m ;;
      vet-*|staticcheck-*) limit=90s ;;
      golangci-lint) limit=4m ;;
      govulncheck) limit=3m ;;
      *) echo "Unknown check: $name" >&2; exit 2 ;;
    esac
    # Лимит включает загрузку зависимостей и сборку; 124 означает тайм-аут.
    (
      cd "$root/$directory" || exit 125
      printf 'Command:'
      printf ' %q' "$@"
      printf '\nDirectory: %s\n\n' "$directory"
      timeout --kill-after=5s "$limit" "$@"
    ) 2>&1 | tee "$out/$name.txt"
    code="${PIPESTATUS[0]}"
    echo "$code" > "$out/$name.exit"
    bash "$root/scripts/audit/check.sh" summary
    exit "$code"
    ;;
  summary)
    {
      echo '# Core audit — Linux'
      echo
      echo 'Счётчики отражают только найденные сообщения, а не полноту проверки.'
      echo 'Issues: строки file.go:line[:column] у анализаторов; у govulncheck — показанные уязвимости.'
      echo 'Ненулевой код требует просмотра лога. NOT RUN — проверка не запускалась; 124/137 — тайм-аут.'
      echo 'Ошибка сборки/загрузки может означать несовместимость с Linux или cgo; это не успешная проверка.'
      echo
      echo '| Проверка / лог | Exit | Races | Issues | Failed tests | Примечание |'
      echo '| --- | --- | --- | --- | --- | --- |'
      for name in "${checks[@]}"; do
        log="$out/$name.txt"
        code="$(cat "$out/$name.exit" 2>/dev/null || echo 'NOT RUN')"
        if [[ ! -f "$log" ]]; then
          echo 'NOT RUN: prerequisite failed or job interrupted.' > "$log"
        fi
        races=$(grep -c '^WARNING: DATA RACE' "$log" || true)
        failed=$(grep -cE '^[[:space:]]*--- FAIL:' "$log" || true)
        issues=0
        case "$name" in
          vet-*|staticcheck-*|golangci-lint)
            issues=$(grep -cE '^[^[:space:]]+\.go:[0-9]+(:[0-9]+)?:' "$log" || true) ;;
          govulncheck)
            issues=$(grep -cE '^Vulnerability #[0-9]+:' "$log" || true) ;;
        esac
        note=''
        if [[ "$code" != 0 ]]; then
          note='Смотрите лог: находки или неполная проверка'
        fi
        if grep -qE '\[build failed\]|build constraints exclude|undefined:|fatal error:|could not import|C source files not allowed' "$log"; then
          note='Ошибка сборки/загрузки; проверьте Linux/cgo и зависимости'
        fi
        printf '| [%s](%s.txt) | %s | %s | %s | %s | %s |\n' \
          "$name" "$name" "$code" "$races" "$issues" "$failed" "$note"
      done
    } > "$out/summary.md"
    ;;
  *)
    echo 'Usage: check.sh init | run NAME DIRECTORY COMMAND... | summary' >&2
    exit 2
    ;;
esac
