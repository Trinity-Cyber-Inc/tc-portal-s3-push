from python:3.6.8

WORKDIR /app

ENV REQUESTS_CA_BUNDLE=/app/ca_certs.pem
ENV TC_API_KEY=
ENV AWS_ACCESS_KEY_ID=
ENV AWS_SECRET_ACCESS_KEY=

COPY ca_certs.pem ca_certs.pem
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .
CMD ["python3", "trinity_events_to_s3.py"]
