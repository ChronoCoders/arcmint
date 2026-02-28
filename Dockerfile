FROM rust:slim AS deps

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

COPY crates/arcmint-core/Cargo.toml crates/arcmint-core/Cargo.toml
COPY crates/arcmint-federation/Cargo.toml crates/arcmint-federation/Cargo.toml
COPY crates/arcmint-gateway/Cargo.toml crates/arcmint-gateway/Cargo.toml
COPY crates/arcmint-wallet/Cargo.toml crates/arcmint-wallet/Cargo.toml
COPY crates/arcmint-merchant/Cargo.toml crates/arcmint-merchant/Cargo.toml
COPY crates/arcmint-lnd/Cargo.toml crates/arcmint-lnd/Cargo.toml
COPY crates/arcmint-adversary/Cargo.toml crates/arcmint-adversary/Cargo.toml
COPY crates/arcmint-loadtest/Cargo.toml crates/arcmint-loadtest/Cargo.toml
COPY tests/integration/Cargo.toml tests/integration/Cargo.toml

RUN mkdir -p crates/arcmint-core/src && echo 'pub fn stub(){}' > crates/arcmint-core/src/lib.rs && \
    mkdir -p crates/arcmint-federation/src && echo 'fn main(){}' > crates/arcmint-federation/src/main.rs && \
    mkdir -p crates/arcmint-federation/src/bin && \
    echo 'fn main(){}' > crates/arcmint-federation/src/bin/coordinator.rs && \
    echo 'fn main(){}' > crates/arcmint-federation/src/bin/keygen.rs && \
    echo 'fn main(){}' > crates/arcmint-federation/src/bin/certgen.rs && \
    echo 'fn main(){}' > crates/arcmint-federation/src/bin/dkg_coordinator.rs && \
    echo 'fn main(){}' > crates/arcmint-federation/src/bin/dkg_participant.rs && \
    mkdir -p crates/arcmint-gateway/src && echo 'fn main(){}' > crates/arcmint-gateway/src/main.rs && \
    mkdir -p crates/arcmint-wallet/src && echo 'fn main(){}' > crates/arcmint-wallet/src/main.rs && \
    mkdir -p crates/arcmint-merchant/src && echo 'fn main(){}' > crates/arcmint-merchant/src/main.rs && \
    mkdir -p crates/arcmint-lnd/src && echo 'pub fn stub(){}' > crates/arcmint-lnd/src/lib.rs && \
    mkdir -p crates/arcmint-adversary/src && echo 'fn main(){}' > crates/arcmint-adversary/src/main.rs && \
    mkdir -p crates/arcmint-loadtest/src && echo 'fn main(){}' > crates/arcmint-loadtest/src/main.rs && \
    mkdir -p tests/integration/src && echo 'pub fn stub(){}' > tests/integration/src/lib.rs

RUN cargo build --release --workspace --features arcmint-federation/dev-keygen 2>/dev/null || true

FROM rust:slim AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=deps /usr/local/cargo/registry /usr/local/cargo/registry
COPY --from=deps /usr/local/cargo/git /usr/local/cargo/git
COPY --from=deps /app/target /app/target

COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY tests tests
RUN cargo build --release --workspace --features arcmint-federation/dev-keygen

FROM debian:trixie-slim

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
COPY --from=build /app/target/release/dkg_coordinator /usr/local/bin/dkg_coordinator
COPY --from=build /app/target/release/dkg_participant /usr/local/bin/dkg_participant

ARG SERVICE_BIN
ENV SERVICE_BIN=${SERVICE_BIN}

CMD ["/bin/sh", "-lc", "/usr/local/bin/${SERVICE_BIN}"]
