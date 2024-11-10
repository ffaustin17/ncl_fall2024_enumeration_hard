FROM rust:1.81 AS builder

ENV CTF_FLAG="THIS_IS_NOT_THE_REAL_FLAG_DO_NOT_SUBMIT_IT"

WORKDIR /challenge

COPY . .

RUN cargo build --release

FROM debian:bookworm
ARG USERNAME=ctf

COPY --from=builder /challenge/target/release/industry-guidelines /challenge/industry-guidelines
#COPY --from=builder /lib/x86_64-linux-gnu/libc.so /lib/x86_64-linux-gnu/libc-2.34.so

RUN useradd -m -s /bin/bash $USERNAME && \
    mkdir -p /challenge && \
    chown -R root:root /challenge && \
    chmod 111 /challenge/industry-guidelines

USER $USERNAME

ENTRYPOINT ["/bin/bash"]
