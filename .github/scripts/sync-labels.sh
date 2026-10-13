#!/usr/bin/env bash
# sync-labels.sh — Sincroniza las labels del repositorio desde .github/labels.yml
# (F1.T12, AGENTS.md §8). Idempotente: crea las que faltan y actualiza color y
# descripción de las existentes. No borra labels ajenas al fichero (protección
# ante ediciones manuales en GitHub).
#
# Uso: bash .github/scripts/sync-labels.sh   (requiere gh autenticado con scope repo)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

labels_file=".github/labels.yml"
[[ -f "$labels_file" ]] || { echo "error: no se encuentra $labels_file" >&2; exit 1; }

# Etiquetas actuales en el repositorio.
existing=$(gh label list --limit 200 --json name --jq '.[].name')

created=0
updated=0
while IFS=$'\t' read -r name color description; do
  [[ -n "$name" ]] || continue
  if printf '%s\n' "$existing" | grep -qxF "$name"; then
    gh label edit "$name" --color "$color" --description "$description" >/dev/null
    updated=$((updated + 1))
  else
    gh label create "$name" --color "$color" --description "$description" >/dev/null
    created=$((created + 1))
  fi
done < <(python3 - "$labels_file" <<'PY'
import sys, yaml
with open(sys.argv[1], encoding="utf-8") as fh:
    for entry in yaml.safe_load(fh):
        print(f"{entry['name']}\t{entry['color']}\t{entry.get('description','')}")
PY
)

echo "sync-labels: $created creadas, $updated actualizadas."
