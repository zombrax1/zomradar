# ZomRadar

A private web dashboard for saved and PCAP-backed live alliance/player data. It
includes accounts, synthetic fallback data, SQLite persistence, and a Docker
entrypoint.

## Run locally

```powershell
python app.py
```

Open <http://localhost:8000>, create an account, upload your own PCAP in
Settings, then use **Live fetch**.

Custom player photos are served from the running game's local BestHTTP cache.
The server automatically detects a connected MuMu ADB device. If ADB is in a
custom location, set `ZOMRADAR_ADB` and optionally `ZOMRADAR_ADB_SERIAL` before
starting the server. `ZOMRADAR_AVATAR_CACHE_DIR` can instead point to a copied
`LocalCache/Content` directory. Missing photos keep the normal fallback avatar
until the game has cached them.

## Run with Docker

```powershell
docker build -t zomradar .
docker run --rm -p 8000:8000 -v zomradar-data:/app/data zomradar
```

Set `ZOMRADAR_DATA_DIR` to change the SQLite directory and
`ZOMRADAR_SECURE_COOKIES=1` behind HTTPS.

## Live data boundary

This repository contains no packet captures, session credentials, or private
account data. Uploaded captures stay in the ignored runtime SQLite database and
are used server-side for live state, alliance, roster, and player-detail reads.
Protect the data directory: a PCAP can contain an authenticated game session.
