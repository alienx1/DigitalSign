.PHONY: run build check fmt lint test clean setup push

run:
	cargo run --bin digitalsign

check:
	cargo check --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets

test:
	cargo test --workspace

clean:
	cargo clean

# --- Container image (see docker/dockerfile) ---
IMAGE_NAME   ?= digitalsign
REGISTRY     ?=
TAG          ?= latest
COMMIT_SHORT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE   := $(shell date +%Y%m%d%H)

# Local-only manifest list name — must not match a real registry tag, or it
# collides with an existing regular image ("image is not a manifest list").
MANIFEST := $(IMAGE_NAME):multiarch

# Installs qemu emulation for cross-arch builds (one-time, if the machine
# doesn't have it yet). On Fedora: sudo dnf install qemu-user-static (binfmt
# registers itself automatically once installed).
setup:
	@if podman run --rm --platform linux/arm64 docker.io/library/alpine uname -m 2>/dev/null | grep -q aarch64; then \
		echo "✅ qemu-aarch64 emulation is available"; \
	else \
		echo "⚠️  arm64 emulation not found"; \
		echo "    Install via: sudo dnf install qemu-user-static (Fedora) or sudo apt install qemu-user-static (Debian/Ubuntu)"; \
		echo "    Or temporarily: podman run --privileged --rm docker.io/tonistiigi/binfmt --install arm64"; \
		exit 1; \
	fi

# Multi-arch build (linux/amd64, linux/arm64) as a local manifest list ($(MANIFEST))
build: setup
	@echo "Building multi-arch manifest (linux/amd64, linux/arm64)..."
	-podman manifest rm $(MANIFEST) 2>/dev/null
	podman build -f docker/dockerfile \
		--platform linux/amd64,linux/arm64 \
		--manifest $(MANIFEST) \
		.

# Push the manifest to REGISTRY (run `make build` first; must set REGISTRY when invoking, e.g. make push REGISTRY=ghcr.io/your-org)
push:
	@if [ -z "$(REGISTRY)" ]; then \
		echo "REGISTRY is not set — usage: make push REGISTRY=ghcr.io/your-org"; \
		exit 1; \
	fi
	podman manifest push --all $(MANIFEST) docker://$(REGISTRY)/$(IMAGE_NAME):$(TAG)
	podman manifest push --all $(MANIFEST) docker://$(REGISTRY)/$(IMAGE_NAME):$(COMMIT_SHORT)
	podman manifest push --all $(MANIFEST) docker://$(REGISTRY)/$(IMAGE_NAME):$(BUILD_DATE)
