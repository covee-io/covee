FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /covee-console ./cmd/covee-console \
    && mkdir /data && chown 10001:10001 /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /covee-console /covee-console
COPY --from=build --chown=10001:10001 /data /data
USER 10001:10001
ENV COVEE_LISTEN=:8088 COVEE_DATA_DIR=/data
EXPOSE 8088
ENTRYPOINT ["/covee-console"]
