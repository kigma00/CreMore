FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
RUN apk add --no-cache ca-certificates
WORKDIR /source
RUN wget -q -O source.tar.gz https://github.com/oauth2-proxy/oauth2-proxy/archive/refs/tags/v7.15.4.tar.gz \
    && echo "52e46276359e8e06cc53e9636f605784b9d6f21819c2592d07f9cf5c1eb78779  source.tar.gz" | sha256sum -c - \
    && tar -xzf source.tar.gz --strip-components=1 \
    && wget -q -O LICENSE https://raw.githubusercontent.com/oauth2-proxy/oauth2-proxy/v7.15.4/LICENSE \
    && echo "89807acf2309bd285f033404ee78581602f3cd9b819a16ac2f0e5f60ff4a473e  LICENSE" | sha256sum -c -
# v7.15.4 pins grpc v1.83.0 (CVE-2026-84304); v1.83.1 is still affected by
# CVE-2026-84445. x/crypto v0.55.0 carries CVE-2026-56855 and CVE-2026-78662.
# Compile the unchanged upstream source with the patched compatible module.
RUN go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.56.0 && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version.VERSION=v7.15.4-cremore.1" \
      -o /out/oauth2-proxy .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/y4rvin/CreMore" \
      org.opencontainers.image.vendor="CreMore contributors" \
      org.opencontainers.image.version="7.15.4-cremore.1"
COPY --from=build /source/LICENSE /licenses/oauth2-proxy/LICENSE
COPY --from=build /out/oauth2-proxy /oauth2-proxy
USER 65532:65532
ENTRYPOINT ["/oauth2-proxy"]
