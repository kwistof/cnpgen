# Build a static cnpgen binary and ship it in a minimal distroless image.
#
# We add a single static `tar` binary (from musl busybox) so `kubectl cp` works
# against the pod: that's how you pull the generated policy files out of an
# in-cluster run. The image stays distroless (no shell, no package manager).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /cnpgen ./cmd/cnpgen

FROM busybox:1.36-musl AS busybox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cnpgen /cnpgen
# Static musl busybox, exposed as `tar` so `kubectl cp <pod>:/out ...` works.
COPY --from=busybox /bin/busybox /usr/bin/tar
ENTRYPOINT ["/cnpgen"]
