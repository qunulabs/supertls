.PHONY: test test-short test-race lint fmt check crosscompile l7 proto-tools proto

# test runs the whole suite, including the slow tests that -short skips.
test:
	go test ./... -count=1

test-short:
	go test ./... -count=1 -short

test-race:
	go test ./... -count=1 -short -race

lint:
	go vet ./...

fmt:
	gofmt -s -w .

# crosscompile builds every supported target from one host, which is the only
# way to notice a platform-specific file breaking another platform.
crosscompile:
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		echo "  $$target"; \
		GOOS=$${target%/*} GOARCH=$${target#*/} go build ./... || exit 1; \
	done

# l7 runs the real-proxy tests. They need docker and are deliberately not in CI;
# see README.md.
l7:
	go test -tags l7proxy -run TestL7 -count=1 -v .

# Proto generation. The toolchain is PINNED, and `proto` refuses to run on
# another one. The generated code is committed and read by every consumer; a
# regeneration on a different protoc rewrites hundreds of lines that have
# nothing to do with the edit, which hides the one line that does, and the wire
# contract is exactly where a hidden line costs a machine nobody can redeploy.
# Moving the pin is a deliberate change: bump the three numbers here, regenerate,
# and review the whole diff.
# Spelled without the leading "v": the three tools disagree about it
# (protoc-gen-go prints "v1.36.11", protoc-gen-go-grpc prints "1.6.2"), so the
# check strips it from both sides rather than encoding one tool's habit.
PROTOC_VERSION      := 3.21.12
PROTOC_GEN_GO       := 1.36.11
PROTOC_GEN_GO_GRPC  := 1.6.2

proto-tools:
	@$(call check_tool,protoc,$(PROTOC_VERSION),install protoc $(PROTOC_VERSION))
	@$(call check_tool,protoc-gen-go,$(PROTOC_GEN_GO),go install google.golang.org/protobuf/cmd/protoc-gen-go@v$(PROTOC_GEN_GO))
	@$(call check_tool,protoc-gen-go-grpc,$(PROTOC_GEN_GO_GRPC),go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$(PROTOC_GEN_GO_GRPC))

# check_tool <command> <pinned version> <how to get it>. A tool that is absent
# reports the same way as one at the wrong version: both mean "do not generate".
define check_tool
	got=$$($(1) --version 2>/dev/null | awk '{print $$NF}' | sed 's/^v//'); \
	if [ "$$got" != "$(2)" ]; then \
		echo "$(1): have $${got:-nothing on PATH}, pinned to $(2) - $(3)"; \
		exit 1; \
	fi
endef

proto: proto-tools
	protoc -I proto \
		--go_out=. --go_opt=module=github.com/qunulabs/supertls \
		--go-grpc_out=. --go-grpc_opt=module=github.com/qunulabs/supertls \
		proto/supertls/v1/tunnel.proto

check: lint test crosscompile
