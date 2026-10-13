#!/usr/bin/env bash
# check-req-ids.sh — Verifica que todo identificador REQ-* citado en la
# documentación existe en docs/REQUIREMENTS.md (REQ-DOC-003, AGENTS.md §14:
# "Inventar requisitos, IDs o decisiones que no estén documentados" está prohibido).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

req_file="docs/REQUIREMENTS.md"
if [[ ! -f "$req_file" ]]; then
  echo "error: no se encuentra $req_file" >&2
  exit 1
fi

# IDs definidos (columna ID de las tablas de REQUIREMENTS.md).
mapfile -t defined < <(grep -oE '\bREQ-[A-Z]+-[0-9]{3}\b' "$req_file" | sort -u)

if [[ ${#defined[@]} -eq 0 ]]; then
  echo "error: no se extrajeron requisitos de $req_file" >&2
  exit 1
fi

missing=0
while IFS= read -r file; do
  # REQUIREMENTS.md es la fuente; se excluye a sí mismo.
  [[ "$file" == "$req_file" ]] && continue
  while IFS= read -r id; do
    if ! printf '%s\n' "${defined[@]}" | grep -qxF "$id"; then
      echo "error: $file cita $id, que no existe en $req_file"
      missing=$((missing + 1))
    fi
  done < <(grep -oE '\bREQ-[A-Z]+-[0-9]{3}\b' "$file" | sort -u)
done < <(git ls-files '*.md')

if [[ $missing -gt 0 ]]; then
  echo "error: $missing identificadores REQ-* inválidos" >&2
  exit 1
fi

echo "check-req-ids: todos los REQ-* citados existen en $req_file."
