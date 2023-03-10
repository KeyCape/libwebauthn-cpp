# Overview
This is an implementation of the WebAuthn API in C++.
The library has been tested on **ubuntu:22.04** 

# Prerequisites
To get started, you can either use the Dockerfile in `.docker` or you run the following commands: 
```bash 
apt install -y libjsoncpp-dev uuid-dev libssl-dev zlib1g-dev libmariadb-dev cmake make git gcc-12 libhiredis-dev libgoogle-glog-dev python3-pip
``` 

```bash 
pip3 install jsonschema
pip3 install jinja2
``` 

Compile drogon: 
```bash 
git clone https://github.com/drogonframework/drogon \
	&& cd drogon \
	&& git submodule update --init \
	&& mkdir build \
	&& cd build \
	&& cmake -DCMAKE_CXX_STANDARD=20 .. \
	&& make -j4 && make install
``` 

# Build and Test
In order to build and test the library run the following commands:

```bash 
mkdir build \ 
cd build \ 
cmake .. \ 
make \ 
ctest
```