/* memory.h */
#ifndef MEMORY_H
#define MEMORY_H

#include "common.h"
#include "utxo.h"
#include "wallet.h"



void zero(void *, size_t);
void zero_multiple(void *, ...);
void zero_and_gcry_free(void *, size_t );
void zero_and_gcry_free_multiple(size_t, void *, ...);
void free_rbf_outputs_array(rbf_output_t **, size_t);
void free_utxos_array(utxo_t **, int *, size_t);
void free_complete_rbf(rbf_data_t *);
void free_addresses_and_keys(char **, key_pair_t **, int);
void free_addresses(char **, size_t);


#endif
