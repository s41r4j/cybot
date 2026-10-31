FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
LABEL org.opencontainers.image.title="CYBOT Web Toolbox" \
      org.opencontainers.image.source="https://github.com/s41r4j/cybot" \
      io.cybot.managed="true" io.cybot.profile="web"
RUN apt-get update && apt-get install -y --no-install-recommends @PACKAGE_PINS@ \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/sh cybot \
    && mkdir -p /workspace/.cybot /data /reports /home/cybot/.cache /home/cybot/.config \
    && chown -R 10001:10001 /workspace /data /reports /home/cybot
COPY gems/ /tmp/gems/
ENV GEM_HOME=/opt/cybot/lib/gems
RUN --network=none gem install --local --ignore-dependencies --no-document --install-dir /opt/cybot/lib/gems /tmp/gems/*.gem \
    && rm -rf /tmp/gems /opt/cybot/lib/gems/cache
COPY bin/ /opt/cybot/bin/
COPY lib/ /opt/cybot/lib/
COPY share/ /opt/cybot/share/
COPY web.lock.json /opt/cybot/manifest/web.lock.json
COPY entrypoint.sh /usr/local/bin/cybot-toolbox
ENV PATH="/opt/cybot/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/home/cybot USER=cybot XDG_CACHE_HOME=/home/cybot/.cache XDG_CONFIG_HOME=/home/cybot/.config \
    PYTHONPATH=/opt/cybot/lib/python PYTHONDONTWRITEBYTECODE=1 \
    CYBOT_TOOLBOX_INTERNAL=1 CYBOT_PACK_AUTO_UPDATE=0 GOMAXPROCS=1 GOMEMLIMIT=768MiB
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cybot-toolbox"]
CMD ["help"]
