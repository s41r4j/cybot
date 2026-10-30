FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
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
