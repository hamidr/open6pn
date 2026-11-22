GOOS   ?= linux
GOARCH ?= $(shell go env GOARCH)
BPF_IMAGE := open6pn-bpf-build

.PHONY: build bpf test vet e2e clean

# The compiled eBPF object is committed, so a plain build needs only Go.
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -o bin/open6pn-$(GOOS)-$(GOARCH) ./cmd/open6pn

# Recompile internal/datapath/bpf/open6pn.c -> open6pn.o (needs Docker).
bpf:
	docker build -q -t $(BPF_IMAGE) -f build/bpf.Dockerfile build
	docker run --rm -v $(CURDIR)/internal/datapath/bpf:/src $(BPF_IMAGE)

test:
	go test ./...

vet:
	GOOS=linux go vet ./...

# Three hosts, real WireGuard and eBPF, in privileged containers (needs Docker).
e2e:
	./test/e2e/run.sh

clean:
	rm -rf bin
