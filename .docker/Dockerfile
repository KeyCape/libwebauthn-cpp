FROM ubuntu:22.04 

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update \
	&& apt install -y libjsoncpp-dev uuid-dev libssl-dev zlib1g-dev libmariadb-dev cmake make git gcc-12 libhiredis-dev libgoogle-glog-dev python3-pip \
	&& rm -rf /var/lib/apt/lists/*

RUN pip3 install jsonschema
RUN pip3 install jinja2

WORKDIR /drogon
RUN git clone https://github.com/drogonframework/drogon \
	&& cd drogon \
	&& git submodule update --init \
	&& mkdir build \
	&& cd build \
	&& cmake -DCMAKE_CXX_STANDARD=20 .. \
	&& make -j4 && make install
RUN rm -rf /drogon