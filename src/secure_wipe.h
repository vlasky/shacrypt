#ifndef SHACRYPT_SECURE_WIPE_H
#define SHACRYPT_SECURE_WIPE_H

#include <stddef.h>

/* Zero N bytes at P in a way the compiler cannot optimise away.  A plain
   memset() immediately before free() or return is a dead store that
   optimising compilers remove; volatile stores are not.  */
static inline void
secure_wipe (void *p, size_t n)
{
  volatile unsigned char *vp = (volatile unsigned char *) p;
  if (p == NULL)
    return;
  while (n-- > 0)
    *vp++ = 0;
}

#endif
