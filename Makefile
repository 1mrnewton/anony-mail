# Publishing configuration for the prebuilt Docker image.
#
# The image is built locally (multi-arch) and pushed to GitHub Container
# Registry, so end users just `docker compose pull` instead of compiling.

IMAGE     ?= ghcr.io/1mrnewton/anony-mail
GHCR_USER ?= 1mrnewton
PLATFORMS ?= linux/amd64,linux/arm64
BUILDER   ?= anony-mail-builder

# Version comes from Cargo.toml (single source of truth).
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

.PHONY: help
help:
	@echo "anony-mail image publishing"
	@echo ""
	@echo "  make release V=X.Y.Z Bump version in Cargo.{toml,lock}, commit and git-tag"
	@echo "  make docker-login   Log in to ghcr.io (needs \$$GHCR_TOKEN; \$$GHCR_USER optional)"
	@echo "  make publish        Build $(PLATFORMS) and push :$(VERSION) and :latest"
	@echo "  make docker-build   Build a single-arch image locally (no push)"
	@echo "  make version        Print the version parsed from Cargo.toml"

.PHONY: version
version:
	@echo $(VERSION)

# Bump the version, commit, and create an annotated git tag in one step:
#   make release V=0.2.0
# Does not push — it prints the exact follow-up commands so nothing leaves your
# machine until you choose to (`git push --follow-tags`, then `make publish`).
.PHONY: release
release:
	@test -n "$(V)" || { echo "usage: make release V=X.Y.Z"; exit 1; }
	@echo "$(V)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$$' || \
		{ echo "error: V must be a semver version like 0.2.0"; exit 1; }
	@test -z "$$(git status --porcelain)" || \
		{ echo "error: working tree is dirty; commit or stash changes first"; exit 1; }
	@git rev-parse -q --verify "refs/tags/v$(V)" >/dev/null && \
		{ echo "error: tag v$(V) already exists"; exit 1; } || true
	@echo "Bumping $(VERSION) -> $(V)"
	@sed -i.bak 's/^version = "$(VERSION)"/version = "$(V)"/' Cargo.toml && rm -f Cargo.toml.bak
	@sed -i.bak '/^name = "anony-mail"$$/{n;s/^version = ".*"/version = "$(V)"/;}' Cargo.lock && rm -f Cargo.lock.bak
	@git add Cargo.toml Cargo.lock
	@git commit -q -m "release: v$(V)"
	@git tag -a "v$(V)" -m "anony-mail v$(V)"
	@echo "Committed and tagged v$(V)."
	@echo "Next:"
	@echo "  git push --follow-tags   # publish the commit + tag to GitHub"
	@echo "  make docker-login && make publish   # build and push the image"

# Log in using a Personal Access Token (classic) with `write:packages` scope.
# Create one at https://github.com/settings/tokens then:
#   export GHCR_TOKEN=ghp_xxx
.PHONY: docker-login
docker-login:
	@test -n "$$GHCR_TOKEN" || { echo "error: set GHCR_TOKEN (PAT with write:packages)"; exit 1; }
	@echo "$$GHCR_TOKEN" | docker login ghcr.io -u "$(GHCR_USER)" --password-stdin

# Ensure a buildx builder capable of multi-platform builds exists.
.PHONY: buildx-init
buildx-init:
	@docker buildx inspect $(BUILDER) >/dev/null 2>&1 || \
		docker buildx create --name $(BUILDER) --driver docker-container >/dev/null
	@docker buildx use $(BUILDER)

# Build for all target platforms and push straight to the registry.
.PHONY: publish
publish: buildx-init
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE):$(VERSION) \
		--tag $(IMAGE):latest \
		--push \
		.

# Build only for the current machine's architecture into the local Docker
# image store (useful for testing before publishing, or for source builds).
.PHONY: docker-build
docker-build:
	docker build --tag $(IMAGE):$(VERSION) --tag $(IMAGE):latest .
