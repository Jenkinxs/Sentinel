#!/usr/bin/env bash
cd /home/atomichome/Desktop/Athena/Sentinel
export PATH="/home/atomichome/Desktop/Athena/Sentinel/.venv/bin:$PATH"
exec python frontend/app.py --host 100.103.206.31 --port 8081
