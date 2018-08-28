// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "eth.h"
#include "biguint.h"
#include "hex.h"
#include "crypto.h"
#include "vch.h"
#include "json.h"
#include "rlp.h"
#include "key.h"

#define PUBKEY_COMPRESSED       0

/* key & address funcionts */

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

/* script funcionts */

int wl_eth_build_script(const char *context,vch_t *script,vch_t *scriptid)
{
    return -1;
}

/* transaction funcionts */

struct eth_transaction
{
    uint256_t nonce;
    uint256_t price;
    uint256_t gas;
    uint256_t value;
    uint160_t to;
    vch_t *data;
    uint8_t v;
    uint256_t r;
    uint256_t s;
    int chainid;
};

static void wl_eth_tx_init(struct eth_transaction *tx)
{
    memset(tx,0,sizeof(struct eth_transaction));
}

static void wl_eth_tx_clear(struct eth_transaction *tx)
{   
    if (tx->data != NULL)
    {
        wl_vch_free(tx->data);
    }
    memset(tx,0,sizeof(struct eth_transaction));
}

static inline int wl_eth_tx_parse_chainid(struct eth_transaction *tx,uint64_t v)
{
    if (UINT256_ISZERO(tx->r) && UINT256_ISZERO(tx->s))
    {
        tx->chainid = v;
    } 
    else
    {
        if (v > 36)
        {
            tx->chainid = (v - 35) / 2;
        }
        else if (v == 27 || v == 28)
        {
            tx->chainid = -4;
        }
        else
        {
            return -1;
        }
        tx->v = v - (tx->chainid * 2 + 35);
    }
    return 0;
}

static int wl_eth_tx_unserialize(vch_t *vch,struct eth_transaction *tx)
{
    rlp_t rlp[9];
    int count;
    wl_eth_tx_clear(tx);
        
    if ((count = wl_rlp_parse_list(wl_vch_data(vch),wl_vch_len(vch),rlp,9)) < 6)
    {
        return -1;
    }

    if ((tx->data = wl_vch_new()) == NULL)
    {
        return -1;
    }

    if (   wl_rlp_get_biguint(&rlp[0],tx->nonce.u8,32) < 0
        || wl_rlp_get_biguint(&rlp[1],tx->price.u8,32) < 0
        || wl_rlp_get_biguint(&rlp[2],tx->gas.u8,32) < 0
        || wl_rlp_get_biguint(&rlp[3],tx->to.u8,20) < 0
        || wl_rlp_get_biguint(&rlp[4],tx->value.u8,32) < 0
        || wl_rlp_get_data(&rlp[5],tx->data) < 0)
    {
        return -1;
    }
    tx->chainid = -4;
    if (count > 6)
    {
        uint64_t v;
        if (wl_rlp_get_uint(&rlp[6],&v) < 0 || v > 0xff)
        {
            return -1;
        }
        if (count == 9)
        {
            if (wl_rlp_get_biguint(&rlp[7],tx->r.u8,32) < 0
                || wl_rlp_get_biguint(&rlp[8],tx->s.u8,32) < 0)
            {
                return -1;
            }
        }
        if (wl_eth_tx_parse_chainid(tx,v) < 0)
        {
            return -1;
        }
    }

    return 0;
}

static int wl_eth_tx_serialize1(struct eth_transaction *tx,vch_t *vch,int withsig)
{
    int ret = -1;
    vch_t *list = wl_vch_new();
    if (list == NULL)
    {
        return -1;
    }
    wl_vch_clear(vch);
    if (   wl_rlp_put_biguint(list,tx->nonce.u8,32) < 0
        || wl_rlp_put_biguint(list,tx->price.u8,32) < 0
        || wl_rlp_put_biguint(list,tx->gas.u8,32) < 0
        || wl_rlp_put_biguint(list,tx->to.u8,20) < 0
        || wl_rlp_put_biguint(list,tx->value.u8,32) < 0
        || wl_rlp_put_data(list,wl_vch_data(tx->data),wl_vch_len(tx->data)) < 0)
    {
        wl_vch_free(list);
        return -1;
    }

    if (withsig)
    {
        uint8_t v = tx->v + (tx->chainid * 2 + 35);
        if (   wl_rlp_put_uint(list,v) < 0
            || wl_rlp_put_biguint(list,tx->r.u8,32) < 0
            || wl_rlp_put_biguint(list,tx->s.u8,32) < 0)
        {
            wl_vch_free(list);
            return -1;
        }
    }
    else if (tx->chainid > 0)
    {
        if (   wl_rlp_put_uint(list,tx->chainid) < 0
            || wl_rlp_put_uint(list,0) < 0
            || wl_rlp_put_uint(list,0) < 0)
        {
            wl_vch_free(list);
            return -1;
        }
    }

    ret = wl_rlp_put_list(vch,list);
    wl_vch_free(list);
    return ret;
}

static int wl_eth_tx_serialize(struct eth_transaction *tx,vch_t *vch,int withsig)
{
    int ret = -1;
    vch_t *list = wl_vch_new();
    if (list == NULL)
    {
        return -1;
    }

    wl_vch_clear(vch);
    if (   wl_rlp_put_biguint(list,tx->nonce.u8,32) < 0
        || wl_rlp_put_biguint(list,tx->price.u8,32) < 0
        || wl_rlp_put_biguint(list,tx->gas.u8,32) < 0
        || wl_rlp_put_biguint(list,tx->to.u8,20) < 0
        || wl_rlp_put_biguint(list,tx->value.u8,32) < 0
        || wl_rlp_put_data(list,wl_vch_data(tx->data),wl_vch_len(tx->data)) < 0)
    {
        wl_vch_free(list);
        return -1;
    }

    if (withsig)
    {
        // uint8_t v = tx->v + (tx->chainid * 2 + 35);
        uint8_t v = tx->v + 27;
        if (   wl_rlp_put_uint(list,v) < 0
            || wl_rlp_put_biguint(list,tx->r.u8,32) < 0
            || wl_rlp_put_biguint(list,tx->s.u8,32) < 0)
        {
            wl_vch_free(list);
            return -1;
        }
    }
    else
    {
        if(tx->chainid > 0)
        {
            if (wl_rlp_put_uint(list, tx->chainid * 2 + 8) < 0 || wl_rlp_put_uint(list, 0) < 0 
            || wl_rlp_put_uint(list, 0) < 0)
            {
                wl_vch_free(list);
                return -1;
            }
        }
    }

    ret = wl_rlp_put_list(vch,list);
    wl_vch_free(list);
    return ret;
}

static inline int wl_eth_tx_fromhex(const char *hex,struct eth_transaction *tx)
{
    int ret = -1;
    vch_t *vch = wl_vch_new_hex(hex);
    if (vch != NULL)
    {
        ret = wl_eth_tx_unserialize(vch,tx);
        wl_vch_free(vch);
    }
    return ret;
}

static inline int wl_eth_tx_fromjson(json_t *json,struct eth_transaction *tx)
{
    json_t *j;
    wl_eth_tx_clear(tx);
    if ((tx->data = wl_vch_new()) == NULL)
    {
        return -1;
    }
    
    if ((j = wl_json_find(json,"nonce")) == NULL || !wl_json_is_string(j))
    {
        return -1;
    }
    wl_uint256_fromhex(&tx->nonce,wl_json_get_string(j));
    
    if ((j = wl_json_find(json,"price")) == NULL || !wl_json_is_string(j))
    {
        return -1;
    }
    wl_uint256_fromhex(&tx->price,wl_json_get_string(j));

    if ((j = wl_json_find(json,"gas")) == NULL || !wl_json_is_string(j))
    {
        return -1;
    }
    wl_uint256_fromhex(&tx->gas,wl_json_get_string(j));

    if ((j = wl_json_find(json,"value")) == NULL || !wl_json_is_string(j))
    {
        return -1;
    }
    wl_uint256_fromhex(&tx->value,wl_json_get_string(j));

    if ((j = wl_json_find(json,"to")) == NULL || !wl_json_is_string(j))
    {
        return -1;
    }
    wl_uint160_fromhex(&tx->to,wl_json_get_string(j));

    if ((j = wl_json_find(json,"data")) != NULL && !wl_json_is_null(j))
    {
        wl_vch_clear(tx->data);
        if (!wl_json_is_string(j) 
            || wl_vch_push_fromhex(tx->data,wl_json_get_string(j)) < 0)
        {
            return -1;
        }
    }

    if ((j = wl_json_find(json,"r")) != NULL && !wl_json_is_null(j))
    {
        if (!wl_json_is_string(j))
        {
            return -1;
        }
        wl_uint256_fromhex(&tx->r,wl_json_get_string(j));
    }

    if ((j = wl_json_find(json,"s")) != NULL && !wl_json_is_null(j))
    {
        if (!wl_json_is_string(j))
        {
            return -1;
        }
        wl_uint256_fromhex(&tx->s,wl_json_get_string(j));
    }

    tx->chainid = -4;
    if ((j = wl_json_find(json,"v")) != NULL && !wl_json_is_null(j))
    {
        uint64_t v;
        char *endp = NULL;
        if (!wl_json_is_string(j))
        {
            return -1;
        }
        v = strtoull(wl_json_get_string(j),&endp,16);
        if (endp == NULL || v > 0xff || wl_eth_tx_parse_chainid(tx,v) < 0)
        {
            return -1;
        }
    }
    return 0;
}

static inline int wl_eth_tx_json(struct eth_transaction *tx,json_t *json)
{
    char hex[65];

    wl_uint256_tohex_compact(&tx->nonce,hex,65);
    if (wl_json_insert(json,wl_json_new_string("nonce",hex)) == NULL)
    {
        return -1;
    }
    wl_uint256_tohex_compact(&tx->price,hex,65);
    if (wl_json_insert(json,wl_json_new_string("price",hex)) == NULL)
    {
        return -1;
    }
    wl_uint256_tohex_compact(&tx->gas,hex,65);
    if (wl_json_insert(json,wl_json_new_string("gas",hex)) == NULL)
    {
        return -1;
    }
    wl_uint256_tohex_compact(&tx->value,hex,65);
    if (wl_json_insert(json,wl_json_new_string("value",hex)) == NULL)
    {
        return -1;
    }
    wl_uint160_tohex(&tx->to,hex,65);
    if (wl_json_insert(json,wl_json_new_string("to",hex)) == NULL)
    {
        return -1;
    }
    return 0;
}

static inline int wl_eth_tx_construct(const char *tx_data,struct eth_transaction *tx)
{
    int ret = -1;
    json_t *json,*jhex;
    if ((json = wl_json_fromstring(tx_data)) == NULL)
    {
        return -1;
    }

    if ((jhex = wl_json_find(json,"hex")) != NULL)
    {
        ret = wl_eth_tx_fromhex(wl_json_get_string(jhex),tx);
    }
    else
    {
        ret = wl_eth_tx_fromjson(json,tx);
    }
    wl_json_free(json);
    return ret;
}

static inline int wl_eth_tx_parse_context(const char *tx_ctxt,vch_t *from)
{
    int ret = -1;
    json_t *json,*jfrom;
    wl_vch_clear(from);
    if (tx_ctxt == NULL)
    {
        return -1;
    }
    if ((json = wl_json_fromstring(tx_ctxt)) == NULL)
    {
        return -1;
    }
    if ((jfrom = wl_json_find(json,"from")) != NULL && wl_json_is_string(jfrom))
    {
        ret = wl_vch_push_string(from,wl_json_get_string(jfrom));
    } 
    wl_json_free(json);
    return ret;
}

static inline int wl_eth_tx_serhash(struct eth_transaction *tx,uint256_t *hash,int withsig)
{
    vch_t *vch = wl_vch_new();
    if (vch == NULL)
    {
        return -1;
    }
    if (wl_eth_tx_serialize(tx,vch,withsig) < 0)
    {
        wl_vch_free(vch);
        return -1;
    }
    wl_hashsha3(wl_vch_data(vch),wl_vch_len(vch),hash);
    wl_vch_free(vch);
    return 0;
}

static inline int wl_eth_tx_serialize_hex(struct eth_transaction *tx,vch_t *vch)
{
    int ret = -1;
    vch_t *ser = wl_vch_new();
    if (ser != NULL && wl_eth_tx_serialize(tx,ser,1) == 0)
    {
        wl_vch_clear(vch);
        ret = wl_vch_push_hex(vch,wl_vch_data(ser),wl_vch_len(ser));
    }
    wl_vch_free(ser);
    return ret;
}

static inline int wl_eth_tx_recover_sender(struct eth_transaction *tx,char sender[41])
{
    vch_t *pubkey = NULL;
    uint256_t hash;
    uint8_t sig[65];
    
    if ((UINT256_ISZERO(tx->r) && UINT256_ISZERO(tx->s))
        || wl_eth_tx_serhash(tx,&hash,0) < 0)
    {
        return -1;
    }

    memcpy(sig,&tx->r,32);
    memcpy(sig + 32,&tx->s,32);
    sig[64] = tx->v;

    if ((pubkey = wl_vch_new()) == NULL)
    {
        return -1;
    }
    if (wl_secp_eth_recover_pubkey(sig,hash.u8,pubkey) < 0
        || wl_eth_get_addr(wl_vch_data(pubkey),sender,41) < 0)
    {
        wl_vch_free(pubkey);
        return -1;
    }
    wl_vch_free(pubkey);
    return 0;
}


int wl_eth_parse_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_json)
{
    json_t *json;
    char sender[41] = {0,};
    struct eth_transaction tx;
    wl_eth_tx_init(&tx);
    if (wl_eth_tx_construct(tx_data,&tx) < 0)
    {
        wl_eth_tx_clear(&tx);
        return -1;
    }

    if ((json = wl_json_new(NULL,WL_JSON_OBJECT)) == NULL)
    {
        wl_eth_tx_clear(&tx);
        return -1;
    }

    if (wl_eth_tx_recover_sender(&tx,sender) == 0
        && wl_json_insert(json,wl_json_new_string("sender",sender)) == NULL)
    {
        wl_json_free(json);
        wl_eth_tx_clear(&tx);
        return -1;
    }
        
    if (wl_eth_tx_json(&tx,json) < 0 || wl_json_tostring(json,tx_json) < 0)
    {
        wl_json_free(json);
        wl_eth_tx_clear(&tx);
        return -1;
    }

    wl_json_free(json);
    wl_eth_tx_clear(&tx);

    return 0;
}

static int wl_eth_tx_sign_from_address(struct eth_transaction *tx,const char *from)
{
    int ret = -1;
    vch_t *sig = NULL;
    uint256_t hash;
    if ( wl_eth_tx_serhash(tx,&hash,0) < 0 || (sig = wl_vch_new()) == NULL)
    {
        return -1;
    }

    if ((ret = wl_key_sign(WALLEVE_COINS_ETH,from,hash.u8,sig)) == 0)
    {
        memcpy(&tx->r,wl_vch_data(sig),32);
        memcpy(&tx->s,&((uint8_t *)wl_vch_data(sig))[32],32);
        tx->v = ((uint8_t *)wl_vch_data(sig))[64];
    }

    wl_vch_free(sig);
    return ret;
}

int wl_eth_sign_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_signed)
{
    int ret = -1;
    vch_t *from = NULL;
    struct eth_transaction tx;
    wl_eth_tx_init(&tx);
    if (wl_eth_tx_construct(tx_data,&tx) < 0)
    {
        wl_eth_tx_clear(&tx);
        return -1;
    }
    if ((from = wl_vch_new()) == NULL 
        || wl_eth_tx_parse_context(tx_ctxt,from) < 0
        || wl_eth_tx_sign_from_address(&tx,wl_vch_string(from)) < 0)
    {
        wl_eth_tx_clear(&tx);
        wl_vch_free(from);
        return -1;
    }

    ret = wl_eth_tx_serialize_hex(&tx,tx_signed);

    wl_vch_free(from);
    wl_eth_tx_clear(&tx);

    return ret;
}

int wl_eth_verify_tx(const char *tx_data,const char *tx_ctxt,vch_t *ret_json)
{
    json_t *json;
    vch_t *from = NULL;
    char sender[41] = {0,};
    struct eth_transaction tx;
    int completed = 0;
    wl_eth_tx_init(&tx);
    if (wl_eth_tx_construct(tx_data,&tx) < 0)
    {
        wl_eth_tx_clear(&tx);
        return -1;
    }


    if ((from = wl_vch_new()) == NULL 
        || wl_eth_tx_parse_context(tx_ctxt,from) < 0)
    {
        wl_eth_tx_clear(&tx);
        wl_vch_free(from);
        return -1;
    }

    if ((json = wl_json_new(NULL,WL_JSON_OBJECT)) == NULL)
    {
        wl_eth_tx_clear(&tx);
        wl_vch_free(from);
        return -1;
    }
    
    wl_json_insert(json,wl_json_new_string("from",wl_vch_string(from)));
    
    if (wl_eth_tx_recover_sender(&tx,sender) == 0)
    {
        wl_json_insert(json,wl_json_new_string("signer",sender));
        if (wl_vch_cmp_string(from,sender) == 0)
        {
            completed = 1;
        }
    }
    wl_json_insert(json,wl_json_new_boolean("completed",completed));

    wl_eth_tx_clear(&tx);
    wl_vch_free(from);

    if (wl_json_tostring(json,ret_json) < 0) 
    {
        wl_json_free(json);
        return -1;
    }

    wl_json_free(json);
    return 0;
}
