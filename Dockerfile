################
##### Builder
FROM alpine:3.16.0 as builder

RUN apk add binutils build-base ca-certificates curl file g++ gcc make patch rust

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN . ~/.cargo/env && rustup target add x86_64-unknown-linux-musl

# Cache downloaded+built dependencies
#COPY Cargo.toml Cargo.lock /usr/src/rencfs/
#RUN mkdir /usr/src/rencfs/src && \
#    echo 'fn main() {}' > /usr/src/rencfs/src/main.rs
#
#RUN . ~/.cargo/env && cd /usr/src/rencfs/ && cargo build --release && \
#    rm -Rvf /usr/src/rencfs/src

# Build our actual code
COPY Cargo.toml Cargo.lock /usr/src/rencfs/
COPY src /usr/src/rencfs/src
RUN . ~/.cargo/env &&  \
    cd /usr/src/rencfs/ &&  \
    cargo build --target x86_64-unknown-linux-musl --release

################
##### Runtime
FROM alpine:3.16.0 AS runtime

RUN apk add fuse3

# Copy application binary from builder image
COPY --from=builder /usr/src/rencfs/target/x86_64-unknown-linux-musl/release/rencfs /usr/local/bin

# Run the application
CMD ["rencfs", "--help"]
