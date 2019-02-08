FROM amazonlinux

LABEL maintainer="robert@aztek.io"

RUN yum -y install python37 python37-pip zip && \
        yum clean all

RUN pip3 install virtualenv && \
        mkdir /Build

COPY cloudtrail_bot.py /Build/cloudtrail_bot.py
# COPY requirements.txt /Build/requirements.txt

RUN virtualenv -p /usr/bin/python3.7 /Build

WORKDIR /Build

RUN source bin/activate
# RUN pip install -r requirements.txt
RUN zip -r /Build.zip \
        cloudtrail_bot.py \
        bin/*

WORKDIR /Build/lib/python3.7/site-packages/
RUN zip -r /Build.zip .

WORKDIR /Build/lib64/python3.7/site-packages/
RUN zip -r /Build.zip .
