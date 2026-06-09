#ifndef CSEC_SHA256_H
#define CSEC_SHA256_H

#include <stddef.h>

/* Compute SHA-256 of `input` (len bytes) into the 32-byte `out`. */
void sha256(const void *input, size_t len, unsigned char out[32]);

#endif /* CSEC_SHA256_H */
