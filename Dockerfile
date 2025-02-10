FROM python:3.12-slim-bullseye
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
ENTRYPOINT [ "python3", "ssh_to_jwks.py" ]