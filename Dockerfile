# syntax=docker/dockerfile:1
# ---- build: fully static musl binary ---------------------------------------------------
FROM rust:1.90-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && cp target/release/docker-nat66 /docker-nat66

# ---- runtime: nothing but the binary ---------------------------------------------------
FROM scratch
COPY --from=build /docker-nat66 /docker-nat66
ENTRYPOINT ["/docker-nat66"]
