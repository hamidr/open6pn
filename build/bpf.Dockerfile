# Toolchain for compiling the eBPF datapath. Used by `make bpf`.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
CMD ["sh", "-c", "clang -O2 -g -Wall -Werror -target bpf -mcpu=v2 -I/usr/include/$(uname -m)-linux-gnu -c open6pn.c -o open6pn.o && llvm-strip -g open6pn.o"]
