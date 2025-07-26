#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > PenMQTT.desktop <<EOF
[Desktop Entry]
Name=PenMQTT
Comment=MQTT Pentest Tool Launcher
Exec=$SCRIPT_DIR/bas.sh
Icon=$SCRIPT_DIR/assets/icon2.jpeg
Terminal=true
Type=Application
Categories=Utility;
Path=$SCRIPT_DIR
EOF

chmod +x PenMQTT.desktop
chmod +x bas.sh
echo "[✓] Launcher 'PenMQTT.desktop' berhasil dibuat di folder ini."
echo "[i] Klik kanan > Allow Launching jika di GNOME Desktop."
