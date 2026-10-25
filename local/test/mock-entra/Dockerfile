# TEST ONLY: windmill-mock-entra:test, used by docker-compose.test.yml. Never deployed.
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/mock-entra .

FROM gcr.io/distroless/static-debian13@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/mock-entra /usr/local/bin/mock-entra
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mock-entra"]
