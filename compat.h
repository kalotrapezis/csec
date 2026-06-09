/* compat.h — cross-platform shim for sockets, threads, mutexes and paths.
   Lets the shared proxy engine (proxy.c) compile unchanged on both Windows
   and POSIX (Linux). Platform frontends include this too. */
#ifndef CSEC_COMPAT_H
#define CSEC_COMPAT_H

#include <stdlib.h>

#ifdef _WIN32
/* ----------------------------------------------------------------- Windows */
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>

  typedef SOCKET sock_t;
  #define INVALID_SOCK   INVALID_SOCKET
  #define closesock      closesocket
  #define strncasecmp    _strnicmp
  #define PATHSEP        "\\"

  static inline void net_init(void) { WSADATA w; WSAStartup(MAKEWORD(2,2), &w); }
  static inline void sleep_ms(int ms) { Sleep((DWORD)ms); }

  typedef CRITICAL_SECTION mutex_t;
  static inline void mutex_init(mutex_t *m)    { InitializeCriticalSection(m); }
  static inline void mutex_lock(mutex_t *m)    { EnterCriticalSection(m); }
  static inline void mutex_unlock(mutex_t *m)  { LeaveCriticalSection(m); }
  static inline void mutex_destroy(mutex_t *m) { DeleteCriticalSection(m); }

  static inline void set_recv_timeout(sock_t s, int ms) {
      DWORD to = (DWORD)ms;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
  }

  /* Spawn a detached thread running a POSIX-style entry: void *fn(void *). */
  typedef struct { void *(*fn)(void *); void *arg; } csec_thunk;
  static DWORD WINAPI csec_tramp(LPVOID p) {
      csec_thunk t = *(csec_thunk *)p; free(p);
      t.fn(t.arg); return 0;
  }
  static inline void spawn_thread(void *(*fn)(void *), void *arg) {
      csec_thunk *t = (csec_thunk *)malloc(sizeof(*t));
      if (!t) return;
      t->fn = fn; t->arg = arg;
      HANDLE h = CreateThread(NULL, 0, csec_tramp, t, 0, NULL);
      if (h) CloseHandle(h); else free(t);
  }

#else
/* ------------------------------------------------------------------- POSIX */
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <strings.h>
  #include <time.h>

  typedef int sock_t;
  #define INVALID_SOCK   (-1)
  #define closesock      close
  #define PATHSEP        "/"

  #ifndef MAX_PATH
  #define MAX_PATH 4096
  #endif

  static inline void net_init(void) { /* nothing to do */ }
  static inline void sleep_ms(int ms) {
      struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
      nanosleep(&ts, NULL);
  }

  typedef pthread_mutex_t mutex_t;
  static inline void mutex_init(mutex_t *m)    { pthread_mutex_init(m, NULL); }
  static inline void mutex_lock(mutex_t *m)    { pthread_mutex_lock(m); }
  static inline void mutex_unlock(mutex_t *m)  { pthread_mutex_unlock(m); }
  static inline void mutex_destroy(mutex_t *m) { pthread_mutex_destroy(m); }

  static inline void set_recv_timeout(sock_t s, int ms) {
      struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  static inline void spawn_thread(void *(*fn)(void *), void *arg) {
      pthread_t th;
      if (pthread_create(&th, NULL, fn, arg) == 0) pthread_detach(th);
  }

#endif

#endif /* CSEC_COMPAT_H */
