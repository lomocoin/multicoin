// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_CRYPTO_H
#define  WALLEVE_CRYPTO_H

#include <stdlib.h>
#include "vch.h"

#define MAX_SECP_SECRET_LEN	(32)
#define MAX_SECP_PUBKEY_LEN	(65)
#define MAX_SECP_SIGNATURE_LEN	(72)

void wl_crypto_init();
void wl_crypto_deinit();

void wl_rand_data(void *data,size_t size);

int wl_secp_verify_secret(void *secret);
int wl_secp_get_pubkey(void *secret,int compress,vch_t *pubkey);
int wl_secp_sign_signature(void *secret,const void *md32,vch_t *sig);
int wl_secp_verify_signature(void *pubkey,int compress,void *md32,void *sig,size_t len);

void wl_hash256d(const void *data,size_t size,void *md32);
void wl_hash160(const void *data,size_t size,void *md20);
void wl_hashsha3(const void *data,size_t size,void *md32);

void wl_right160(const void *md32,void *md20);

#endif //WALLEVE_CRYPTO_H
