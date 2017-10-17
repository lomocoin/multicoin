// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "multicoin.h"
#include "version.h"
#include "crypto.h"
#include "key.h"
#include "script.h"
#include "tx.h"

int wl_multicoin_init(void)
{
    wl_crypto_init();
    wl_key_init();
    wl_script_init();
    return 0;
}

void wl_multicoin_deinit(void)
{
    wl_script_clear();
    wl_key_clear();
    wl_crypto_deinit();
}

int wl_multicoin_version(vch_t *ver)
{
    if (ver != NULL)
    {
        wl_vch_clear(ver);
        return wl_vch_push_sprintf(ver,WL_VERSION_FMT,WL_MULTICOIN_MAJOR,
                                                      WL_MULTICOIN_MINOR);
    }
    return -1;
}

int wl_multicoin_key_create(coin_t coin,vch_t *addr)
{
    if (addr == NULL)
    {
        return -1;
    }
    return wl_key_create(coin,addr);
}

int wl_multicoin_key_import(coin_t coin,const char *privkey,vch_t *addr)
{
    if (privkey == NULL && addr == NULL)
    {
        return -1;
    }
    return wl_key_import(coin,privkey,addr);
}

void wl_multicoin_key_remvoe(coin_t coin,const char *addr)
{
    if (addr != NULL)
    {
        wl_key_remvoe(coin,addr);
    }
}

int wl_multicoin_key_privkey(coin_t coin,const char *addr,vch_t *privkey)
{
    if (privkey == NULL && addr == NULL)
    {
        return -1;
    }
    return wl_key_privkey(coin,addr,privkey);
}

int wl_multicoin_key_pubkey(coin_t coin,const char *addr,vch_t *pubkey)
{
    if (pubkey == NULL && addr == NULL)
    {
        return -1;
    }
    return wl_key_pubkey(coin,addr,pubkey);
}

int wl_multicoin_script_addnew(coin_t coin,const char *context,vch_t *addr)
{
    if (context == NULL || addr == NULL)
    {
        return -1;
    }
    return wl_script_addnew(coin,context,addr);
}

void wl_multicoin_script_remove(coin_t coin,const char *addr)
{
    if (addr != NULL)
    {
        wl_script_remove(coin,addr);
    }
}

int wl_multicoin_script_export(coin_t coin,const char *addr,vch_t *script)
{
    if (addr == NULL || script == NULL)
    {
        return -1;
    }
    return wl_script_export(coin,addr,script);
}

int wl_multicoin_tx_parse(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_json)
{
    if (tx_data == NULL || tx_ctxt == NULL || tx_json == NULL)
    {
        return -1;
    }
    return wl_tx_parse(coin,tx_data,tx_ctxt,tx_json);
}

int wl_multicoin_tx_sign(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_signed)
{
    if (tx_data == NULL || tx_ctxt == NULL || tx_signed == NULL)
    {
        return -1;
    }
    return wl_tx_sign(coin,tx_data,tx_ctxt,tx_signed);
}

int wl_multicoin_tx_verify(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *ret_json)
{
    if (tx_data == NULL || tx_ctxt == NULL || ret_json == NULL)
    {
        return -1;
    }
    return wl_tx_verify(coin,tx_data,tx_ctxt,ret_json);
}


