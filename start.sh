#!/bin/sh
python3 /app/gen_static.py
exec gunicorn xct_server:app -b 0.0.0.0:8001 -w 2 --timeout 300
