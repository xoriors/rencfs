################
##### Builder
FROM alpine:3.16.0 as builder

RUN apk add binutils build-base ca-certificates curl file g++ gcc libressl-dev make patch rust

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN . ~/.cargo/env && rustup target add x86_64-unknown-linux-musl

# Cache downloaded+built dependencies
COPY Cargo.toml Cargo.lock /usr/src/encryptedfs/
RUN mkdir /usr/src/encryptedfs/src && \
    echo 'fn main() {}' > /usr/src/encryptedfs/src/main.rs

RUN . ~/.cargo/env && cd /usr/src/encryptedfs/ && cargo build --release && \
    rm -Rvf /usr/src/encryptedfs/src

# Build our actual code
COPY src /usr/src/encryptedfs/src
RUN touch /usr/src/encryptedfs/src/main.rs
RUN . ~/.cargo/env &&  \
    cd /usr/src/encryptedfs/ &&  \
    cargo build --target x86_64-unknown-linux-musl --release

################
##### Runtime
FROM alpine:3.16.0 AS runtime

RUN apk add fuse3

# Copy application binary from builder image
COPY --from=builder /usr/src/encryptedfs/target/x86_64-unknown-linux-musl/release/encryptedfs /usr/local/bin

# Run the application
CMD ["encryptedfs", "--help"]
