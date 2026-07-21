FROM python:3.12-slim
WORKDIR /app
COPY app.py README.md ./
COPY outputs/wos_saas.py outputs/wos_search_dashboard.html ./outputs/
EXPOSE 8000
CMD ["python", "app.py"]
