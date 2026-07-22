FROM python:3.12-slim
WORKDIR /app
COPY app.py README.md ./
COPY outputs/wos_live_roster.py outputs/wos_saas.py outputs/wos_search_dashboard.html ./outputs/
COPY work/analyze_wos_pcap.py work/extract_wos_observed.py ./work/
EXPOSE 8000
CMD ["python", "app.py"]
