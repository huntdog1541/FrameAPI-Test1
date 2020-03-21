FROM ubuntu:devel

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y apt-utils build-essential gcc g++ python3 python3-pip cmake nano curl git procps clang \
    && apt-get install -y curl openssh-server nano software-properties-common apt-transport-https pkg-config 

RUN ln -s /usr/bin/python3.8 /usr/bin/python && ln -s /usr/bin/pip3 /usr/bin/pip 

# RUN apt-get install -y openjdk-13-jdk libjna-java maven 

# RUN curl -sL https://deb.nodesource.com/setup_13.x | bash && apt-get install -y nodejs \
#    && npm install -g eslint && apt-get install -y yarn

# RUN wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
#    && dpkg -i packages-microsoft-prod.deb && add-apt-repository universe && apt-get update && apt-get install -y apt-transport-https && apt-get update \
#    && apt-get install -y dotnet-sdk-3.0 && export DOTNET_CLI_TELEMETRY_OPTOUT=1

# RUN git clone https://github.com/emscripten-core/emsdk.git && cd emsdk \
#    && ./emsdk install latest && ./emsdk activate latest && echo "source /emsdk/emsdk_env.sh" >> ~/.bashrc

RUN git clone https://github.com/keystone-engine/keystone.git \
    && cd keystone && mkdir build && cd build && ../make-share.sh && make install && echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig \
    && cd ../bindings/python && make install3 

RUN git clone https://github.com/aquynh/capstone.git && cd capstone \
    && ./make.sh && ./make.sh install && cd bindings/python && python setup.py install 

RUN git clone https://github.com/unicorn-engine/unicorn.git && cd unicorn \
    && ./make.sh && ./make.sh install && cd bindings/python && python setup.py install 