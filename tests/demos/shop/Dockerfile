FROM python:3.12-slim
RUN pip install --no-cache-dir psycopg2-binary
COPY services.py /services.py
ENTRYPOINT ["python3", "/services.py"]
