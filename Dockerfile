# syntax=docker/dockerfile:1.7
# Builds all Orbital binaries as static musl executables.
FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev cmake make perl clang g++ linux-headers
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace --locked \
 && mkdir /out \
 && cp target/release/orbital-orchestrator target/release/orbital-agent target/release/orbital /out/ \
 && size=$(stat -c %s /out/orbital-agent) \
 && echo "orbital-agent: $size bytes" \
 && test "$size" -lt 10485760 || { echo "agent size gate failed: >= 10MB"; exit 1; }

FROM alpine:3.20 AS orchestrator
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 orbital \
 && mkdir -p /var/lib/orbital/recordings /usr/share/orbital/agents && chown -R orbital /var/lib/orbital
COPY --from=builder /out/orbital-orchestrator /usr/local/bin/
COPY --from=builder /out/orbital-agent /tmp/orbital-agent
RUN mv /tmp/orbital-agent /usr/share/orbital/agents/orbital-agent-$(uname -m)
USER orbital
VOLUME /var/lib/orbital
EXPOSE 8443 8444
ENTRYPOINT ["/usr/local/bin/orbital-orchestrator"]

# Debian box with sshd + OpenSSH client + the CLI: plays the "host" and the "client" in the E2E.
FROM debian:bookworm-slim AS testbox
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && ssh-keygen -A \
 && for u in alice carol deploy; do useradd -m -s /bin/bash $u && usermod -p '*' $u; done
COPY --from=builder /out/orbital /usr/local/bin/orbital
CMD ["/usr/sbin/sshd", "-D", "-e"]
