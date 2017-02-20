#include "p2p/peerid.h"

int peerid_init_gen( peerid_t *peerid, int bits ){

    int r = -1;

    memset( peerid, 0, sizeof(peerid_t) );

    if( !peerid || (bits % 1024) != 0 )
        goto cleanup;

    if( pcrypto_pk_rsa_init_gen( &peerid->pk, bits ) != 0 )
        goto cleanup;

    if( peerid_calc_mhash( peerid ) != 0 )
        goto cleanup;

    r = 0;
cleanup:
    return r;
}

int peerid_init_key( peerid_t *peerid, pcrypto_pk_t *pk, int pub ){

    int r = -1;

    memset( peerid, 0, sizeof(peerid_t) );

    if( !peerid || !pk )
        goto cleanup;

    if( pcrypto_pk_init_pk( &peerid->pk, &pk->ctx, pub ) != 0 )
        goto cleanup;

    if( peerid_calc_mhash( peerid ) != 0 )
        goto cleanup;

    r = 0;
cleanup:
    return r;
}

int peerid_init_pemder( peerid_t *peerid, uint8_t *pem_or_der, size_t len, int pub ){

    int r = -1;

    memset( peerid, 0, sizeof(peerid_t) );

    if( !peerid || !pem_or_der || !len )
        goto cleanup;

    if( pcrypto_pk_init_pemder( &peerid->pk, pem_or_der, len, pub ) != 0 )
        goto cleanup;

    if( peerid_calc_mhash( peerid ) != 0 )
        goto cleanup;

    r = 0;
cleanup:
    return r;
}

void peerid_free( peerid_t *peerid ){

    if( !peerid )
        return;

    mhash_free( &peerid->mhash );
    pcrypto_pk_free( &peerid->pk );
    memset( peerid, 0, sizeof(peerid_t) );
}

int peerid_calc_mhash( peerid_t *peerid ){

    int r = -1;
    uint8_t digest[PCRYPTO_PK_RSA_HASH_LEN];

    if( pcrypto_pk_hash( &peerid->pk, digest ) != 0 )
        goto cleanup;

    if( mhash_init_raw( &peerid->mhash, MHASH_SHA2_256, PCRYPTO_PK_RSA_HASH_LEN, digest ) != 0 )
        goto cleanup;

    r = 0;
cleanup:
    return r;
}
