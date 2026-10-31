# The build helper supplies only verified runtime assets in a temporary context.
# No compiler, source checkout, download archives or build cache enters this image.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
LABEL org.opencontainers.image.title="CYBOT Core Toolbox" \
      org.opencontainers.image.source="https://github.com/s41r4j/cybot" \
      io.cybot.managed="true" io.cybot.profile="core"
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap=7.95+dfsg-3 nmap-common=7.95+dfsg-3 ca-certificates=20250419+deb13u1 jq=1.7.1-6+deb13u4 libpcap0.8t64=1.10.5-2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/sh cybot \
    && mkdir -p /workspace/.cybot /data /reports /home/cybot/.cache /home/cybot/.config \
    && chown -R 10001:10001 /workspace /data /reports /home/cybot
COPY bin/ /opt/cybot/bin/
COPY share/ /opt/cybot/share/
COPY rules/ /opt/cybot/rules/
COPY core.lock.json /opt/cybot/manifest/core.lock.json
COPY entrypoint.sh /usr/local/bin/cybot-toolbox
ENV PATH="/opt/cybot/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/home/cybot XDG_CACHE_HOME=/home/cybot/.cache XDG_CONFIG_HOME=/home/cybot/.config \
    CYBOT_TOOLBOX_INTERNAL=1 CYBOT_PACK_AUTO_UPDATE=0 GOMAXPROCS=1 GOMEMLIMIT=768MiB SYFT_CHECK_FOR_APP_UPDATE=false \
    NUCLEI_TEMPLATES_DIRECTORY=/opt/cybot/share/nuclei-templates \
    SECLISTS_DIRECTORY=/opt/cybot/share/seclists
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cybot-toolbox"]
CMD ["help"]
