# Use an argument to specify the Ubuntu version, with a default
ARG UBUNTU_VERSION=20.04

# Use the specified Ubuntu version from the .env file
FROM ubuntu:${UBUNTU_VERSION}

ARG USER_NAME=developer
ARG USER_HOME=/home/developer
ARG PROJECT_NAME=rencfs

ENV USER_NAME=${USER_NAME}
ENV USER_HOME=${USER_HOME}
ENV PROJECT_NAME=${PROJECT_NAME}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    sudo  \
    git  \
    curl \
    gcc \
    pkg-config \
    build-essential \
    libssl-dev \
    fuse3

RUN useradd -m -s /bin/bash -d ${USER_HOME} ${USER_NAME} \
    && echo "${USER_NAME} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USER_NAME} \
    && chmod 0440 /etc/sudoers.d/${USER_NAME}

# Switch to the new user
USER ${USER_NAME}
WORKDIR ${USER_HOME}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Set the environment variables needed for Rust
ENV PATH="${USER_HOME}/.cargo/bin:${PATH}"

WORKDIR ${USER_HOME}/${PROJECT_NAME}

# Command to keep the container running
CMD ["sleep", "infinity"]
