FROM amazonlinux

LABEL maintainer="robert@aztek.io"

RUN yum install python2-pip zip -y

RUN pip install virtualenv && \
        mkdir /Build

COPY cloudtrail_bot.py /Build/cloudtrail_bot.py
# COPY requirements.txt /Build/requirements.txt

RUN virtualenv -p /usr/bin/python2.7 /Build

RUN cd /Build && \
        source bin/activate # && \
        # pip install -r requirements.txt

RUN cd /Build/ && \
        zip /Build.zip \
            cloudtrail_bot.py \
            bin/*

RUN cd /Build/lib/python2.7/site-packages/ && \
        zip -r /Build.zip . && \
        cd /Build/lib64/python2.7/site-packages/ && \
        zip -r /Build.zip .
