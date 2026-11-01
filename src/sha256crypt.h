#ifndef SHACRYPT_SHA256CRYPT_H
#define SHACRYPT_SHA256CRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Size of a buffer able to hold any SHA-256 crypt result including the
   terminating NUL: "$5$" + "rounds=999999999$" + 16-byte salt + "$"
   + 43 hash characters + NUL.  */
#define SHA256_CRYPT_OUTPUT_MAX 81

/* Reentrant, thread-safe SHA-256 crypt.  Writes the result into BUFFER
   (BUFLEN bytes) and returns BUFFER.  Returns NULL with errno set to
   ERANGE if the buffer is too small or ENOMEM if allocation fails.  */
char *sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen);

#ifdef __cplusplus
}
#endif

#endif
