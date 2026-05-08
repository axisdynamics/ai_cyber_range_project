# c_service/Makefile — AI Cyber Range Lab Service (macOS + Linux)
CC      := $(shell command -v gcc 2>/dev/null || echo cc)
SRC     := src/lab_service.c
OUTDIR  := build
BIN     := $(OUTDIR)/lab_service
BIN_V   := $(OUTDIR)/lab_service_vulnerable
BIN_D   := $(OUTDIR)/lab_service_debug

# Detect platform
UNAME_S := $(shell uname -s)

# Common flags (work on both macOS and Linux)
COMMON := -Wall -Wextra -Wformat-security -fno-strict-aliasing

# Hardened: platform-specific linker hardening
ifeq ($(UNAME_S),Darwin)
  # macOS: clang handles PIE automatically; no -z flags (Linux-only)
  HARDENED_FLAGS := $(COMMON) -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
  HARDENED_LINK  :=
  VULN_FLAGS     := $(COMMON) -O1 -fno-stack-protector -DLAB_VULNERABLE=1
  VULN_LINK      :=
  DEBUG_FLAGS    := $(COMMON) -O0 -g3 -DLAB_DEBUG=1
  DEBUG_LINK     :=
else
  # Linux: full hardening flags
  HARDENED_FLAGS := $(COMMON) -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
  HARDENED_LINK  := -Wl,-z,relro,-z,now -pie
  VULN_FLAGS     := $(COMMON) -O1 -fno-stack-protector -DLAB_VULNERABLE=1
  VULN_LINK      := -no-pie
  DEBUG_FLAGS    := $(COMMON) -O0 -g3 -fsanitize=address,undefined -DLAB_DEBUG=1
  DEBUG_LINK     := -fsanitize=address,undefined
endif

.PHONY: all hardened vulnerable debug test clean

all: hardened vulnerable debug

hardened: $(BIN)
$(BIN): $(SRC) | $(OUTDIR)
	$(CC) $(HARDENED_FLAGS) $(SRC) -o $@ $(HARDENED_LINK)
	@echo "[✓] Hardened: $@ (platform=$(UNAME_S))"

vulnerable: $(BIN_V)
$(BIN_V): $(SRC) | $(OUTDIR)
	$(CC) $(VULN_FLAGS) $(SRC) -o $@ $(VULN_LINK)
	@echo "[✓] Vulnerable: $@ (mitigations disabled — lab only)"

debug: $(BIN_D)
$(BIN_D): $(SRC) | $(OUTDIR)
	$(CC) $(DEBUG_FLAGS) $(SRC) -o $@ $(DEBUG_LINK) || \
	$(CC) $(COMMON) -O0 -g3 $(SRC) -o $@
	@echo "[✓] Debug: $@"

$(OUTDIR):
	@mkdir -p $(OUTDIR)

test: $(BIN)
	cd .. && ./$(BIN) selftest

clean:
	@rm -rf $(OUTDIR)
