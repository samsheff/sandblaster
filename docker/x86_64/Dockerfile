FROM --platform=linux/amd64 rust:1.91-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        pkg-config \
        time \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

ENV CARGO_HOME=/cargo

CMD ["/bin/bash"]
