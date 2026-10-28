# The build helper supplies only verified runtime assets in a temporary context.
# No compiler, source checkout, download archives or build cache enters this image.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
LABEL org.opencontainers.image.title="CYBOT Core Toolbox" \
      org.opencontainers.image.source="https://github.com/s41r4j/cybot" \
      io.cybot.managed="true" io.cybot.profile="core"
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates=20250419~deb12u2 nmap=7.93+dfsg1-1 nmap-common=7.93+dfsg1-1 jq=1.6-2.1+deb12u3 libpcap0.8=1.10.3-1 \
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
