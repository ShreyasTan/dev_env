from alpine:3.14

ENV DOCKER_ENV=true
RUN apk add --no-cache python3-dev
RUN apk add py3-pip \
    && pip3 install --upgrade pip

WORKDIR /var/log/load_balancer
WORKDIR /opt

COPY . /opt/load_balancer

EXPOSE 5015

ENTRYPOINT ["python3"]
CMD ["load_balancer/bin/app.py"]
