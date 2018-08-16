FROM rust:latest

ARG GIT_REV=master

# Install dependencies
RUN cd /root && curl -sLO https://deb.nodesource.com/setup_6.x \
    && chmod +x setup_6.x && ./setup_6.x \
    && apt-get install -y nodejs supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Build xori
RUN git clone --depth=1 https://github.com/endgameinc/xori.git /root/xori \
    && cd /root/xori \
    && git reset --hard ${GIT_REV} \
    && cd /root/xori && cargo build --release \
    && rm -rf /root/xori/src && rm -rf /root/xori/doc
RUN cd /root/xori/gui && npm install 

# Activating default config
RUN cp -v /root/xori/xori.json.example /root/xori/xori.json

COPY xori*.conf /etc/supervisor/conf.d/
EXPOSE 3000 5000

WORKDIR /root/xori/gui

ENTRYPOINT ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
