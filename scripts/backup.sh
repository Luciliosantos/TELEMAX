#!/bin/bash
# Backup do TELEMAX: banco + uploads. Uso: ./scripts/backup.sh /destino
set -euo pipefail
DEST="${1:-./backups}"
STAMP=$(date +%F-%H%M)
DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DEST"
sqlite3 "$DIR/instance/telemax.db" ".backup '$DEST/telemax-$STAMP.db'"
[ -d "$DIR/instance/uploads" ] && tar czf "$DEST/uploads-$STAMP.tar.gz" -C "$DIR/instance" uploads
find "$DEST" -name "*.db" -mtime +14 -delete
find "$DEST" -name "*.tar.gz" -mtime +14 -delete
echo "Backup concluído em $DEST"
