#!/usr/bin/env bash
# Start the Encryption Lab with PHP's built-in web server.
# Usage:  ./start.sh          (or: bash start.sh)
#         ./start.sh 8080     (use a different port)

PORT="${1:-8000}"
cd "$(dirname "$0")" || exit 1   # run from this script's folder

if ! command -v php >/dev/null 2>&1; then
  echo "PHP is not installed. On macOS run:  brew install php"
  exit 1
fi

echo "Encryption Lab running at  http://localhost:$PORT   (press Ctrl+C to stop)"
php -S "localhost:$PORT" -t public
