# Статический бинарник (musl), итоговый образ ~2 МБ.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY tests ./tests
RUN cargo build --release --locked && strip target/release/xtg

FROM scratch
COPY --from=build /src/target/release/xtg /xtg
ENTRYPOINT ["/xtg"]
CMD ["--help"]
