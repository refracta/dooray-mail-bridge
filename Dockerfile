FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/dooray-mail-bridge ./cmd/dooray-mail-bridge \
    && mkdir -p /out/data \
    && chown 10001:10001 /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dooray-mail-bridge /dooray-mail-bridge
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
WORKDIR /data
EXPOSE 1993 1465
ENTRYPOINT ["/dooray-mail-bridge"]
