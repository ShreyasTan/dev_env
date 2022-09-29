from alpine:3.14

ENV DOCKER_ENV=true
RUN apk add --no-cache python3-dev
RUN apk add py3-pip \
    && pip3 install --upgrade pip

WORKDIR /var/log/hss
WORKDIR /opt

COPY . /opt/hss

RUN pip3 install -r hss/config/docker/requirements.txt

EXPOSE 5014 5016

ENTRYPOINT ["python3"]
CMD ["hss/bin/app.py"]
