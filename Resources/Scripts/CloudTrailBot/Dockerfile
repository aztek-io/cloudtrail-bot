FROM amazonlinux

LABEL maintainer="robert@aztek.io"

RUN yum -y install python37 zip && \
        yum clean all

RUN mkdir -p /tmp/Build

COPY [".", "/tmp/Build"]

WORKDIR /tmp/Build

RUN pip-3.7 install -r requirements.txt --target .
RUN zip -r9 /tmp/Build.zip .

