FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
LABEL org.opencontainers.image.title="CYBOT Browser Toolbox" \
      org.opencontainers.image.source="https://github.com/s41r4j/cybot" \
      io.cybot.managed="true" io.cybot.profile="browser"
RUN apt-get update && apt-get install -y --no-install-recommends @PACKAGE_PINS@ \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/sh cybot \
    && mkdir -p /workspace/.cybot /data /reports /home/cybot/.cache /home/cybot/.config \
    && chown -R 10001:10001 /workspace /data /reports /home/cybot \
    && chmod 0755 /home/cybot
COPY bin/ /opt/cybot/bin/
COPY share/ /opt/cybot/share/
COPY browser.lock.json /opt/cybot/manifest/browser.lock.json
COPY entrypoint.sh /usr/local/bin/cybot-toolbox
ENV PATH="/opt/cybot/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/home/cybot USER=cybot XDG_CACHE_HOME=/home/cybot/.cache XDG_CONFIG_HOME=/home/cybot/.config \
    PYTHONDONTWRITEBYTECODE=1 CYBOT_BROWSER_EXECUTABLE=/usr/bin/chromium \
    CYBOT_TOOLBOX_INTERNAL=1 CYBOT_PACK_AUTO_UPDATE=0 GOMAXPROCS=1 GOMEMLIMIT=768MiB
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cybot-toolbox"]
CMD ["help"]
