################
##### Builder
FROM alpine:3.19.1 as builder

RUN apk update && apk upgrade && apk add binutils build-base ca-certificates curl file g++ gcc make patch

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN . ~/.cargo/env && rustup target add x86_64-unknown-linux-musl

RUN . ~/.cargo/env && rustup default nightly && rustup update

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
COPY examples /usr/src/rencfs/examples
RUN . ~/.cargo/env &&  \
    cd /usr/src/rencfs/ &&  \
    cargo build --target x86_64-unknown-linux-musl --release

################
##### Runtime
FROM alpine:3.19.1 AS runtime

RUN apk update && apk upgrade && apk add fuse3
RUN apk upgrade busybox --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main

# Copy application binary from builder image
COPY --from=builder /usr/src/rencfs/target/x86_64-unknown-linux-musl/release/rencfs /usr/local/bin

ARG USER=rencfs
ENV HOME /home/$USER

# install sudo as rootdocker
RUN apk add --update sudo

# add new user
RUN adduser -D $USER \
        && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
        && chmod 0440 /etc/sudoers.d/$USER

USER $USER
WORKDIR $HOME

# Run the application
CMD ["rencfs", "--help"]
