// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdlib.h>
#include <time.h>
#include "crypto.h"
#include "biguint.h"

#if __BIG_ENDIAN__ || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||\
    __ARMEB__ || __THUMBEB__ || __AARCH64EB__ || __MIPSEB__
#define WORDS_BIGENDIAN        1
#endif
#define DETERMINISTIC          1
#define USE_BASIC_CONFIG       1
#define ENABLE_MODULE_RECOVERY 1

#pragma clang diagnostic push
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wconditional-uninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "secp256k1/src/basic-config.h"
#include "secp256k1/src/secp256k1.c"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop


static secp256k1_context *_ctx = NULL;
static uint256_t _secp256k1n,_secp256k1n_rs;

void wl_crypto_init()
{
    _ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    srandom(time(NULL));
    wl_uint256_fromhex(&_secp256k1n,"115792089237316195423570985008687907852837564279074904382605163141518161494337");
    _secp256k1n_rs = wl_uint256_rshift(_secp256k1n);
}

void wl_crypto_deinit()
{
    if (_ctx)
    {
        secp256k1_context_destroy(_ctx);
        _ctx = NULL;
    }
}

void wl_rand_data(void *data,size_t size)
{
    size_t i = 0;
    uint8_t *p = data;
    if (p != NULL)
    {
        while (i++ < size)
        {
            *p++ = random();
        }
    }
}

int wl_secp_verify_secret(void *secret)
{
    if (_ctx != NULL && secret != NULL)
    {
        if (secp256k1_ec_seckey_verify(_ctx,secret))
        {
            return 0;
        }
    }
    return -1;
}

int wl_secp_get_pubkey(void *secret,int compress,vch_t *pubkey)
{
    secp256k1_pubkey pk;
    size_t len = compress ? 33 : 65;
    unsigned int flags = compress ? SECP256K1_EC_COMPRESSED      
                                  : SECP256K1_EC_UNCOMPRESSED;

    if (_ctx != NULL && secret != NULL && pubkey != NULL)
    {
        if (secp256k1_ec_pubkey_create(_ctx,&pk,secret) 
            && wl_vch_resize(pubkey,len) == 0)
        {
            if (secp256k1_ec_pubkey_serialize(_ctx,wl_vch_data(pubkey),&len,&pk,flags)
                && len == wl_vch_len(pubkey))
            {
                return 0;
            }
        }
    }
    return -1;
}

int wl_secp_sign_signature(void *secret,const void *md32,vch_t *sig)
{
    secp256k1_ecdsa_signature s;
    size_t len = MAX_SECP_SIGNATURE_LEN;
    if (_ctx != NULL && secret != NULL && md32 != NULL && sig != NULL)
    {
        if (secp256k1_ecdsa_sign(_ctx,&s,md32,secret,secp256k1_nonce_function_rfc6979, NULL)
            && wl_vch_resize(sig,len) == 0)
        {
            if (secp256k1_ecdsa_signature_serialize_der(_ctx,wl_vch_data(sig), &len, &s))
            {
                wl_vch_resize(sig,len);
                return 0;
            }
        }
    }
    return -1; 
}

int wl_secp_verify_signature(void *pubkey,int compress,void *md32,void *sig,size_t len)
{
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature s;
     
    if (_ctx != NULL && pubkey != NULL && md32 != NULL && sig != NULL)
    {
        if (secp256k1_ec_pubkey_parse(_ctx, &pk, pubkey,(compress ? 33 : 65))
            && secp256k1_ecdsa_signature_parse_der(_ctx, &s, sig, len))
        {
            secp256k1_ecdsa_signature_normalize(_ctx,&s,&s);
            if (secp256k1_ecdsa_verify(_ctx,&s,md32,&pk) == 1)
            {
                return 0;
            }
        }
    }
    return -1;
}

int wl_secp_eth_sign_signature(void *secret,const void *md32,vch_t *sig)
{
    int v = 0;
    uint256_t u;

    secp256k1_ecdsa_recoverable_signature s;
    if (!secp256k1_ecdsa_sign_recoverable(_ctx,&s,md32,secret,NULL,NULL))
    {
        return -1;
    }
    if (wl_vch_resize(sig,64) < 0)
    {
        return -1;
    }
    secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx,wl_vch_data(sig),&v,&s);

    u = ((uint256_t *)wl_vch_data(sig))[1];
    if (wl_uint256_compare(u,_secp256k1n_rs) > 0)
    {
        ((uint256_t *)wl_vch_data(sig))[1] = wl_uint256_minus(_secp256k1n,u);
        v ^= 1;
    }
    return wl_vch_push_uchar(sig,v);
}

int wl_secp_eth_recover_pubkey(void *sig65,void *md32,vch_t *pubkey)
{
    size_t len = 65;
    int v = ((uint8_t *)sig65)[64];
    if (v > 3) 
    {
        return -1;
    }
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(_ctx, &sig,sig65, v))
    {
        return -1;
    }
    secp256k1_pubkey pk;
    if (!secp256k1_ecdsa_recover(_ctx,&pk,&sig,md32))
    {
        return -1;
    }
    
    if (wl_vch_resize(pubkey,len) < 0)
    {
        return -1;
    }
    secp256k1_ec_pubkey_serialize(_ctx,wl_vch_data(pubkey),&len,&pk,SECP256K1_EC_UNCOMPRESSED);
    return (len == 65 ? 0 : -1);
}

#include "rmd160.h"
static void wl_hash_rmd160(void *data,size_t size,void *md20)
{
#define RMDsize 160
    uint8_t *bytes = data;
    dword buf[RMDsize / 32];
    dword x[16];
    size_t n;
    MDinit(buf);
    for (n = size; n > 63; n -= 64)
    {
        memcpy(x,bytes,64);
        bytes += 64;
        compress(buf,x);
    }
    MDfinish(buf, bytes, size, 0);
    memcpy(md20,buf,20);
}

static void wl_hash_sha256(const void *data,size_t size,void *md32)
{
    secp256k1_sha256_t hash;
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash,data,size);
    secp256k1_sha256_finalize(&hash,md32);
}

void wl_hash256d(const void *data,size_t size,void *md32)
{
    uint8_t hash[32];
    wl_hash_sha256(data,size,hash);
    wl_hash_sha256(hash,32,md32);
}

void wl_hash160(const void *data,size_t size,void *md20)
{
    uint8_t hash[32];
    wl_hash_sha256(data,size,hash);
    wl_hash_rmd160(hash,32,md20);
}

#include "sha3.h"

void wl_hashsha3(const void *data,size_t size,void *md32)
{
    sha3_256(md32,32,data,size); 
}

void wl_right160(const void *md32,void *md20)
{
    memcpy(md20,((uint8_t*)md32) + 12,20);
}
