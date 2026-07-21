# ZomRadar

A complete, token-free web demo for alliance and player exploration. It includes
the dashboard, account system, package activation flow, synthetic demo data,
SQLite persistence, and a production-ready Docker entrypoint.

## Run locally

```powershell
python app.py
```

Open <http://localhost:8000>, create the first account, choose a demo package,
then load saved state `1755`.

## Run with Docker

```powershell
docker build -t zomradar .
docker run --rm -p 8000:8000 -v zomradar-data:/app/data zomradar
```

Set `ZOMRADAR_DATA_DIR` to change the SQLite directory and
`ZOMRADAR_SECURE_COOKIES=1` behind HTTPS.

## Live data boundary

This public repository contains no packet captures, session credentials, or
private account data. Live scanning and game controls require a separate,
self-owned private collector. The included web app remains fully runnable using
synthetic demo data.
