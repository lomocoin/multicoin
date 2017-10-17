// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "eth.h"
#include "hex.h"
#include "crypto.h"
#include "vch.h"

#define PUBKEY_COMPRESSED       0

int wl_eth_is_compressed()
{
    return PUBKEY_COMPRESSED;
}

int wl_eth_get_addr(const uint8_t *pubkey,char *addr,size_t len)
{
    int i;
    char *p = addr;
    uint256_t hash = UINT256_ZERO;
    uint160_t right;
    wl_hashsha3(pubkey + 1,64,&hash);
    wl_right160(&hash,&right);
    if (len < 41)
    {
        return -1;
    }
    for (i = 0;i < 20;i++)
    {
        *p++ = wl_hex_to_char(right.u8[i] >> 4);
        *p++ = wl_hex_to_char(right.u8[i] & 15); 
    }
    return 0;
}

int wl_eth_get_priv(const uint8_t *secret,vch_t *privkey)
{
    wl_vch_clear(privkey);
    return wl_vch_push_hex(privkey,secret,32);
}

int wl_eth_set_priv(const char *privkey,uint8_t *secret)
{
    int h,l;
    const char *hex = privkey;
    if (strlen(privkey) != 32 * 2)
    {
        return -1;
    }
    while (*hex != '\0')
    {
        if ((h = wl_hex_to_int(*hex++)) < 0
            || (l = wl_hex_to_int(*hex++)) < 0)
        {
            return -1;
        }
        *secret++ = (h << 4) | l;
    }
    return 0;
}

int wl_eth_build_script(const char *context,vch_t *script,vch_t *scriptid)
{
    return -1;
}
int wl_eth_parse_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_json)
{
    return -1;
}
int wl_eth_sign_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_signed)
{
    return -1;
}
int wl_eth_verify_tx(const char *tx_data,const char *tx_ctxt,vch_t *ret_json)
{
    return -1;
}
