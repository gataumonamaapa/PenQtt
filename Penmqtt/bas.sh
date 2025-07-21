#!/bin/bash

echo "===[ MQTT Pentest Setup Script - Jalankan GUI Langsung ]==="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$ROOT_DIR/venv" ]; then
    echo "[+] Membuat virtual environment..."
    python3 -m venv --system-site-packages "$ROOT_DIR/venv"
fi

source "$ROOT_DIR/venv/bin/activate"

echo "[+] Menginstall dependencies..."
pip install --upgrade pip > /dev/null
pip install -r "$ROOT_DIR/requirements.txt" || {
    echo "[!] Gagal install dependencies. Jalankan manual jika perlu."
}

echo "[+] Menjalankan PenMQTT GUI..."
sudo -E "$ROOT_DIR/venv/bin/python3" "$ROOT_DIR/ui/splashscreen.py"
