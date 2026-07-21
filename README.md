# WOS local dashboard

Local Python API and browser dashboard for inspecting user-supplied game captures.

## Run

```powershell
python -m venv .venv
.venv\Scripts\pip install -r outputs\requirements.txt
python outputs\wos_private_api.py
```

Database credentials are read from `WOS_MYSQL_HOST`, `WOS_MYSQL_PORT`,
`WOS_MYSQL_USER`, `WOS_MYSQL_PASSWORD`, and `WOS_MYSQL_DATABASE`.

## Security

Never commit packet captures, databases, logs, browser traces, environment files,
or generated state. Captures can contain reusable session credentials. The
repository allow-list in `.gitignore` excludes those artifacts by default.
