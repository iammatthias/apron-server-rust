# Builds aprond from the bundle tools/deploy/deploy.sh assembles: the crate
# and its vendored dependencies with .cargo/config.toml pointing at them. The
# build never touches the network. The web client has its own image,
# deploy/caddy.Dockerfile.
FROM rust:1.99.0-bookworm AS build
LABEL systems.farfield.project=apron
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY vendor vendor
COPY src src
RUN cargo build --release --locked --offline --bin aprond

FROM debian:bookworm-slim
LABEL systems.farfield.project=apron
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin apron \
	&& mkdir -p /data \
	&& chown apron:apron /data
COPY --from=build /src/target/release/aprond /usr/local/bin/aprond
USER apron
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aprond"]
