#include <stdio.h>

#include <pcrypto/base58.h>
#include <pcrypto/base64.h>

#include "p2p/mhash.h"

int mhash_init_raw( mhash_t *mhash, uint8_t type, uint8_t len, uint8_t *digest ){

  if( !mhash || !len || !digest )
    return -1;

  memset( mhash, 0, sizeof(mhash_t) );
  mhash->type = type;
  mhash->len = len;
  mhash->digest = malloc( len );
  memcpy( mhash->digest, digest, len );

  return 0;
}


int mhash_init( mhash_t *mhash, const char *mhash_str, int enc ){

  uint8_t *mhash_bin = 0;
  size_t mhash_bin_len = 0;
  uint8_t type, len;
  int r = -1;

  if(!mhash || !mhash_str)
    goto exit;

  switch( enc ){
    case MHASH_ENC_HEX:
      mhash_bin_len = strlen(mhash_str) / 2;
      mhash_bin = malloc( mhash_bin_len );
      mhash_hex2bin( mhash_str, mhash_bin );
    break;

    case MHASH_ENC_BASE32:
      //Not implemented
      goto exit;
    break;

    case MHASH_ENC_BASE58:
      mhash_bin_len = strlen(mhash_str); //optimize me
      mhash_bin = malloc( mhash_bin_len );
      if( pcrypto_base58_decode( mhash_str, mhash_bin, &mhash_bin_len ) != 0 )
        goto exit;
    break;

    case MHASH_ENC_BASE64:
      mhash_bin_len = strlen(mhash_str); //optimize me
      mhash_bin = malloc( mhash_bin_len );
      if( pcrypto_base64_decode( mhash_str, mhash_bin, &mhash_bin_len ) != 0 )
        goto exit;
    break;

    default:
      goto exit;
    break;

  }

  type = mhash_bin[0];
  len = mhash_bin[1];
  if( len != mhash_bin_len - 2 ) /* Bug or attack */
    goto exit;

  if( mhash_init_raw( mhash, type, len, mhash_bin+2 ) != 0 )
    goto exit;

  r = 0;
 exit:
  free( mhash_bin );
  return r;
}


void mhash_free( mhash_t *mhash ){

  if( !mhash )
    return;

  if( mhash->digest ){
    memset( mhash->digest, 0, mhash->len );
    free( mhash->digest );
  }

}


int mhash_to_bin( mhash_t *mhash, uint8_t *binary, size_t binary_len ){

  int r = -1;

  if( !mhash || !binary || binary_len < mhash->len + 2 )
    goto exit;

  binary[0] = mhash->type;
  binary[1] = mhash->len;
  memcpy( binary + 2, mhash->digest, mhash->len );

  r = 0;
 exit:
  return r;
}


int mhash_encode( mhash_t *mhash, char *encoded, size_t encoded_len, int enc ){

  int r = -1;
  uint8_t *mhash_bin = 0;
  size_t mhash_bin_len = 0;

  if( !mhash || !encoded || encoded_len == 0 )
    goto exit;

  if( enc == MHASH_ENC_HEX && encoded_len < (mhash->len * 2) + 1 ) // Little check for the hex encoding procedure
    goto exit;

  mhash_bin_len = mhash->len + 2;
  mhash_bin = malloc( mhash_bin_len );

  if( mhash_to_bin( mhash, mhash_bin, mhash_bin_len ) != 0 )
    goto exit;

  switch( enc ){

    case MHASH_ENC_HEX:
      mhash_bin2hex( encoded, mhash_bin, mhash_bin_len );
    break;

    case MHASH_ENC_BASE32:
      //Not implemented
      goto exit;
    break;


    case MHASH_ENC_BASE58:
      if( pcrypto_base58_encode( encoded, encoded_len, mhash_bin, mhash_bin_len ) != 0 )
        goto exit;
    break;

    case MHASH_ENC_BASE64:
      if( pcrypto_base64_encode( encoded, encoded_len, mhash_bin, mhash_bin_len ) != 0 )
        goto exit;
    break;

    default:
      goto exit;
    break;

  }

  r = 0;
 exit:
  free( mhash_bin );
  return r;

}

void mhash_hex2bin( const char *hex, uint8_t *bin ){
  int i, k, len;
	char tmp[4];

	len = strlen(hex);

	for(i=0, k=0; i<len; i+=2, k++){
		memcpy( tmp, hex+i, 2 );
		tmp[2] = 0;
		bin[k] = strtoul( tmp, 0, 16 );
	}
}

void mhash_bin2hex( char *hex, uint8_t *bin, size_t bin_len ){

  size_t i;

  for(i=0; i<bin_len; i++){
    sprintf(hex+(i*2), "%02x", bin[i]);
  }

}
