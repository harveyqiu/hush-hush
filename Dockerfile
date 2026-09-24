# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure Go (modernc.org/sqlite), so a fully static binary with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hush-hush . \
 && mkdir -p /out/data

# ---- runtime ----------------------------------------------------------------
# distroless/static: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hush-hush /usr/local/bin/hush-hush
# The data directory is created owned by the runtime user with mode 0700;
# a named volume mounted here inherits that on first use.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data

# Inside the container the server must listen on all interfaces so Docker
# can forward to it. Keep the *published* port on the host's loopback
# (-p 127.0.0.1:8080:8080) unless a proxy on another host needs it.
ENV DB_PATH=/data/hush.db \
    LISTEN_ADDR=0.0.0.0:8080

USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/hush-hush", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hush-hush"]
CMD ["serve"]
