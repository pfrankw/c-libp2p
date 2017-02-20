#ifndef PEERID_H
#define PEERID_H

#include <stdint.h>

#include <pcrypto/pk.h>

#include <p2p/mhash.h>

typedef struct {
    mhash_t mhash; /* SHA-256 multihash of a RSA public key */
    pcrypto_pk_t pk;
} peerid_t;


int peerid_init_gen     ( peerid_t *peerid, int bits );
int peerid_init_key     ( peerid_t *peerid, pcrypto_pk_t *pk, int priv );
int peerid_init_pemder  ( peerid_t *peerid, uint8_t *pem_or_der, size_t len, int pub );

void peerid_free    ( peerid_t *peerid );

/* Internal use only */
int peerid_calc_mhash( peerid_t *peerid );

#endif
