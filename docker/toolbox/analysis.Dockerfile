# Build the C-backed parser separately; only its static binary enters runtime.
FROM semgrep/semgrep:1.172.0@sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b AS javascript-builder
USER root
RUN apk add --no-cache gcc=15.2.0-r2 musl-dev=1.2.5-r24
COPY go/ /opt/go/
COPY jsluice-source/ /src/
ENV PATH="/opt/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    CGO_ENABLED=1 CGO_CFLAGS="-O2 -g -std=c11" GOMAXPROCS=1 GOMEMLIMIT=512MiB GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off
WORKDIR /src
RUN mkdir /out \
    && go build -mod=vendor -p 1 -trimpath -buildvcs=false -ldflags='-linkmode external -extldflags=-static' -o /out/jsluice ./cmd/jsluice \
    && go version -m /out/jsluice > /out/jsluice-compiler.txt \
    && gcc --version >> /out/jsluice-compiler.txt \
    && apk info -v >> /out/jsluice-compiler.txt \
    && rm -rf /root/.cache/go-build

# The upstream multi-architecture image is pinned; no registry rules are fetched.
FROM semgrep/semgrep:1.172.0@sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b
LABEL org.opencontainers.image.title="CYBOT Code Analysis Toolbox" \
      org.opencontainers.image.source="https://github.com/s41r4j/cybot" \
      io.cybot.managed="true" io.cybot.profile="analysis"
USER root
RUN mkdir -p /workspace/.cybot /data /reports /home/cybot/.cache /home/cybot/.config \
    && chown -R 10001:10001 /workspace /data /reports /home/cybot
COPY go/ /opt/go/
COPY bin/ /opt/cybot/bin/
COPY --from=javascript-builder /out/jsluice /opt/cybot/bin/jsluice
COPY share/ /opt/cybot/share/
COPY --from=javascript-builder /out/jsluice-compiler.txt /opt/cybot/share/builds/jsluice-compiler.txt
COPY lib/ /opt/cybot/lib/
COPY rules/ /opt/cybot/rules/
COPY analysis.lock.json /opt/cybot/manifest/analysis.lock.json
COPY javascript.lock.json /opt/cybot/manifest/javascript.lock.json
COPY entrypoint.sh /usr/local/bin/cybot-toolbox
ENV PATH="/opt/cybot/bin:/opt/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/home/cybot USER=cybot XDG_CACHE_HOME=/home/cybot/.cache XDG_CONFIG_HOME=/home/cybot/.config \
    CYBOT_TOOLBOX_INTERNAL=1 CYBOT_PACK_AUTO_UPDATE=0 GOMAXPROCS=1 GOMEMLIMIT=768MiB \
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off \
    GOCACHE=/home/cybot/.cache/go-build GOPATH=/home/cybot/.cache/go \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SETTINGS_FILE=/home/cybot/.config/semgrep-settings.yml
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cybot-toolbox"]
CMD ["help"]
