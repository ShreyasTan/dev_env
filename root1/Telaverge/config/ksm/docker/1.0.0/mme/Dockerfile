from alpine:3.14

ENV DOCKER_ENV=true
RUN apk add --no-cache python3-dev
RUN apk add py3-pip \
    && pip3 install --upgrade pip

WORKDIR /var/log/mme
WORKDIR /opt

COPY . /opt/mme

RUN pip3 install -r mme/config/docker/requirements.txt

EXPOSE 5013

ENTRYPOINT ["python3"]
CMD ["mme/bin/app.py"]
