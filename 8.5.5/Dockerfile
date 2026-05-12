FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    pkg-config \
    libxml2-dev \
    bison \
    re2c \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch php-8.5.5 --depth 1 https://github.com/php/php-src.git /php-src \
    && cd /php-src \
    && ./buildconf --force \
    && CFLAGS='-g -O0' \
       ./configure --disable-all --enable-cli --enable-debug \
       --without-pear --disable-cgi --disable-phpdbg \
    && make -j$(nproc) \
    && rm -rf /php-src/.git

ENV USE_ZEND_ALLOC=0

WORKDIR /work
