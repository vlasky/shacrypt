#ifndef SHACRYPT_SHA512CRYPT_H
#define SHACRYPT_SHA512CRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Size of a buffer able to hold any SHA-512 crypt result including the
   terminating NUL: "$6$" + "rounds=999999999$" + 16-byte salt + "$"
   + 86 hash characters + NUL.  */
#define SHA512_CRYPT_OUTPUT_MAX 124

/* Reentrant, thread-safe SHA-512 crypt.  Writes the result into BUFFER
   (BUFLEN bytes) and returns BUFFER.  Returns NULL with errno set to
   ERANGE if the buffer is too small or ENOMEM if allocation fails.  */
char *sha512_crypt_r (const char *key, const char *salt, char *buffer, int buflen);

#ifdef __cplusplus
}
#endif

#endif
