FROM rust:slim AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY tests tests
RUN cargo build --release --workspace

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/target/release/coordinator /usr/local/bin/coordinator
COPY --from=build /app/target/release/arcmint-federation /usr/local/bin/arcmint-federation
COPY --from=build /app/target/release/arcmint-gateway /usr/local/bin/arcmint-gateway
COPY --from=build /app/target/release/arcmint-merchant /usr/local/bin/arcmint-merchant
COPY --from=build /app/target/release/arcmint-wallet /usr/local/bin/arcmint-wallet
COPY --from=build /app/target/release/arcmint-adversary /usr/local/bin/arcmint-adversary
COPY --from=build /app/target/release/arcmint-loadtest /usr/local/bin/arcmint-loadtest
COPY --from=build /app/target/release/keygen /usr/local/bin/keygen
COPY --from=build /app/target/release/certgen /usr/local/bin/certgen
COPY --from=build /app/target/release/certgen /usr/local/bin/certgen
COPY --from=build /app/target/release/certgen /usr/local/bin/certgen
COPY --from=build /app/target/release/dkg_coordinator /usr/local/bin/dkg_coordinator
COPY --from=build /app/target/release/dkg_participant /usr/local/bin/dkg_participant

ARG SERVICE_BIN
ENV SERVICE_BIN=${SERVICE_BIN}

CMD ["/bin/sh", "-lc", "/usr/local/bin/${SERVICE_BIN}"]
