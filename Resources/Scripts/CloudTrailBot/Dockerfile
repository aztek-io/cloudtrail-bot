FROM amazonlinux

LABEL maintainer="robert@aztek.io"

RUN yum -y install python37 zip && \
        yum clean all

RUN pip3 install virtualenv && \
        mkdir -p /tmp/Build

COPY [".", "/tmp/Build"]

RUN virtualenv -p /usr/bin/python3.7 /tmp/Build

WORKDIR /tmp/Build

RUN source bin/activate
RUN pip3.7 install -r requirements.txt

RUN zip -r /tmp/Build.zip \
        cloudtrail_bot.py \
        bin/*

WORKDIR /tmp/Build/lib/python3.7/site-packages/
RUN zip -r /tmp/Build.zip .

WORKDIR /tmp/Build/lib64/python3.7/site-packages/
RUN zip -r /tmp/Build.zip .
