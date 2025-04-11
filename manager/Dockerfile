FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's#http://archive.ubuntu.com/#http://mirrors.tuna.tsinghua.edu.cn/#' /etc/apt/sources.list;
RUN apt-get update --fix-missing && apt-get upgrade -y
RUN apt-get update && apt-get install -y wget --fix-missing

WORKDIR /

## Install golang
RUN wget --no-check-certificate https://dl.google.com/go/go1.17.3.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.17.3.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

## Install the dependencies
ADD . / /root/go/src/github.com/chwzx/MPCTest/
WORKDIR /root/go/src/github.com/chwzx/MPCTest
RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go install
ENV PATH="/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Start the MPC server
ENTRYPOINT ["MPCTest"]
