FROM python:3

RUN apt update && apt install inotify-tools -y
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
RUN chmod +x /app/watch.sh
ENTRYPOINT ["./watch.sh"]
