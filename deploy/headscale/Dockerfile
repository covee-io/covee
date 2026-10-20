# Generated image context is prepared by scripts/build_headscale.py using the
# digest-pinned official Go builder recorded in source-lock.json.
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
FROM ${RUNTIME_IMAGE}
ARG SOURCE_COMMIT
ARG PATCHSET_SHA256
LABEL org.opencontainers.image.title="Covee hardened Headscale" \
      org.opencontainers.image.version="0.29.4-covee.1" \
      org.opencontainers.image.source="https://github.com/juanfont/headscale" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      io.covee.source-tree-sha256="${PATCHSET_SHA256}" \
      io.covee.go-version="1.26.9"
COPY --chown=10001:10001 headscale /headscale
COPY --chown=10001:10001 LICENSE /usr/share/doc/headscale/LICENSE
COPY --chown=10001:10001 state /var/lib/headscale
USER 10001:10001
WORKDIR /var/lib/headscale
EXPOSE 8080/tcp 3478/udp
ENTRYPOINT ["/headscale"]
CMD ["serve", "--config", "/etc/headscale/config.yaml"]
