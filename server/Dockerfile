FROM python:3.12.3-alpine3.19
RUN apk --update add bash nano

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt
CMD python3 main.py
