CC      = i686-w64-mingw32-gcc
CFLAGS  = -std=c99 -O2 -Wall -Wextra -DWIN32_LEAN_AND_MEAN
LDFLAGS = -static -lws2_32 -ladvapi32 -lcrypt32 -lcomctl32 -lcomdlg32 -lshell32 -mwindows

TARGET = csec.exe
SRCS   = csec.c filter.c

$(TARGET): $(SRCS) filter.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	del /Q $(TARGET) 2>nul || true
