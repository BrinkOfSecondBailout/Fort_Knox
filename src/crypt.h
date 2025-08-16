/* crypt.h */

#ifndef CRYPT_H
#define CRYPT_H

#include "gcrypt.h"

#define NEED_LIBGCRYPT_VERSION "1.10.1"

gcry_error_t init_gcrypt();


#endif
