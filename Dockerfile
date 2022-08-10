FROM golang:alpine3.16 as builder
RUN CGO_ENABLED=0 go install github.com/open-policy-agent/conftest@latest

FROM scratch
COPY --from=builder /go/bin/conftest /opt/
COPY policies/ /policies/
ENTRYPOINT ["/opt/conftest", "test", "-p", "/policies", "--all-namespaces"]
