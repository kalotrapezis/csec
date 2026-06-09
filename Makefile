# CSec — cross-platform build.
#   make            native build (Linux: ./csec, via cc)
#   make windows    cross-compile the Windows GUI build (csec.exe, via MinGW)
#   make clean

UNAME_S := $(shell uname -s)

SHARED = proxy.c filter.c sha256.c

ifeq ($(UNAME_S),Linux)
# ---- Linux (native) -------------------------------------------------------
CC      = cc
CFLAGS  = -std=gnu11 -O2 -Wall -Wextra
LDLIBS  = -pthread
TARGET  = csec
SRCS    = csec_posix.c transparent.c $(SHARED)

$(TARGET): $(SRCS) proxy.h compat.h filter.h sha256.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

else
# ---- Other native (fallback to POSIX frontend) ----------------------------
CC      = cc
CFLAGS  = -std=gnu11 -O2 -Wall -Wextra
LDLIBS  = -pthread
TARGET  = csec
SRCS    = csec_posix.c transparent.c $(SHARED)

$(TARGET): $(SRCS) proxy.h compat.h filter.h sha256.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)
endif

# ---- Windows (MinGW cross-compile, runnable from Linux) -------------------
WIN_CC     = i686-w64-mingw32-gcc
WIN_CFLAGS = -std=gnu11 -O2 -Wall -Wextra
WIN_LDLIBS = -static -lws2_32 -ladvapi32 -lcomctl32 -lcomdlg32 -lshell32 -mwindows

windows: csec.c $(SHARED) proxy.h compat.h filter.h sha256.h
	$(WIN_CC) $(WIN_CFLAGS) -o csec.exe csec.c $(SHARED) $(WIN_LDLIBS)

# ---- Linux packages (.deb for Mint, .rpm for Fedora) — needs nfpm ---------
# Install nfpm once: https://nfpm.goreleaser.com/install/
NFPM = nfpm

deb: csec
	@mkdir -p dist
	$(NFPM) pkg -f packaging/nfpm.yaml -p deb -t dist/

rpm: csec
	@mkdir -p dist
	$(NFPM) pkg -f packaging/nfpm.yaml -p rpm -t dist/

package: deb rpm
	@echo "Packages in dist/:" && ls -1 dist/*.deb dist/*.rpm 2>/dev/null

clean:
	rm -f csec
	rm -f dist/*.deb dist/*.rpm
	@echo "(note: tracked csec.exe is left in place; run 'make windows' to rebuild it)"
