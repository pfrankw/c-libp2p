/*
   code name
   0x11 sha1
   0x12 sha2-256
   0x13 sha2-512
   0x14 sha3-512
   0x15 sha3-384
   0x16 sha3-256
   0x17 sha3-224
   0x18 shake-128
   0x19 shake-256
   0x40 blake2b
   0x41 blake2s
 */

#ifndef MHASH_H
#define MHASH_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MHASH_SHA1 0x11
#define MHASH_SHA2_256 0x12
#define MHASH_SHA2_512 0x13
#define MHASH_SHA3_512 0x14
#define MHASH_SHA3_384 0x15
#define MHASH_SHA3_256 0x16
#define MHASH_SHA3_224 0x17
#define MHASH_SHAKE_128 0x18
#define MHASH_SHAKE_256 0x19
#define MHASH_BLAKE2B 0x40
#define MHASH_BLAKE2S 0x41


#define MHASH_ENC_HEX 0
#define MHASH_ENC_BASE32 1
#define MHASH_ENC_BASE58 2
#define MHASH_ENC_BASE64 3

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t type;
    uint8_t len;
    uint8_t *digest;
} mhash_t;

int   mhash_init        ( mhash_t *mhash, const char *mhash_str, int enc );
int   mhash_init_raw    ( mhash_t *mhash, uint8_t type, uint8_t len, uint8_t *digest );
void  mhash_free        ( mhash_t *mhash );

int   mhash_to_bin      ( mhash_t *mhash, uint8_t *binary, size_t binary_len );
int   mhash_encode      ( mhash_t *mhash, char *encoded, size_t encoded_len, int enc );

/* UTILS */
void  mhash_hex2bin     ( const char *hex, uint8_t *bin );      //Bin size WILL of course BE half the size of hex
void  mhash_bin2hex     ( char *hex, uint8_t *bin, size_t bin_len );

#ifdef __cplusplus
}
#endif

#endif
