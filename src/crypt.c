/* crypt.c */
#include "common.h"
#include "crypt.h"

gcry_error_t init_gcrypt() {
	gcry_error_t err = GPG_ERR_NO_ERROR;
	const char *version =  gcry_check_version(NEED_LIBGCRYPT_VERSION);
	if (!version) {
                fprintf(stderr, "libgcrypt is too old (need %s, have %s)\n",
                        NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
                exit(EXIT_FAILURE);
        }
	err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	if (err) {
		fprintf(stderr, "Warning suspension failed\n");
                exit(EXIT_FAILURE);
	}
        err = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
        if (err) {
		fprintf(stderr, "Secure memory enabling failed\n");
                exit(EXIT_FAILURE);
	}
	err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	if (err) {
		fprintf(stderr, "Enabling memory warnings failed\n");
                exit(EXIT_FAILURE);
	}
	err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (err) {
		fprintf(stderr, "Gcrypt initialization completion failed\n");
                exit(EXIT_FAILURE);
	}
	err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P);
	return err;
	
}

