FROM python:3.9-slim-bullseye

RUN apt update && apt install inotify-tools -y

WORKDIR /app

COPY requirements.txt /app
RUN pip install -r requirements.txt

COPY . /app
RUN chmod +x /app/watch.sh

ENTRYPOINT ["./watch.sh"]
