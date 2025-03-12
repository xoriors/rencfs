# Use the specified Ubuntu version from the .env file
FROM ubuntu:latest 

#ARG USER_NAME=developer
#ARG USER_HOME=/home/developer
#ARG PROJECT_NAME=rencfs

#ENV USER_NAME=${USER_NAME}
#ENV USER_HOME=${USER_HOME}
#ENV PROJECT_NAME=${PROJECT_NAME}

#ENV DEBIAN_FRONTEND=noninteractive

# Install Python and Rust
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        curl \
        git \
        gcc \
        build-essential \
        fuse3 \
        python3 \
        python3-pip \
        python3.12-venv && \
    rm -rf /var/lib/apt/lists/*
RUN python3 -m venv venv
RUN alias python=python3

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN . ~/.cargo/env && rustup update 

# Set the environment variables needed for Rust
ENV PATH="${HOME}/.cargo/bin:${PATH}" 

#RUN useradd -m -s /bin/bash -d ${USER_HOME} ${USER_NAME} \
#    && echo "${USER_NAME} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USER_NAME} \
#    && chmod 0440 /etc/sudoers.d/${USER_NAME}

## Switch to the new user
#USER ${USER_NAME}
#WORKDIR ${USER_HOME}



#WORKDIR ${USER_HOME}/${PROJECT_NAME}

# Command to keep the container running
CMD ["sleep", "infinity"]
