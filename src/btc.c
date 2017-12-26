// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btc.h"
#include "biguint.h"
#include "buff.h"
#include "json.h"
#include "key.h"
#include "script.h"

#include "base58.h"
#include "crypto.h"
#include "sato.h"



#define PUBKEY_COMPRESSED	1

enum
{
#if ! TESTNET
    PUBKEY_PREFIX = 0,  // bitcoin: addresses begin with 'L'
    SCRIPT_PREFIX = 5,  // bitcoin: addresses begin with 's'
    PRIVKEY_PREFIX = PUBKEY_PREFIX + 128,
#else
    PUBKEY_PREFIX = 111,
    SCRIPT_PREFIX = 196,
    PRIVKEY_PREFIX = PUBKEY_PREFIX + 128,
#endif
};

static inline double wl_btc_tocoin(uint64_t value)
{
    return (((double)value) / 100000000.0);
}

static inline int wl_btc_extract_address(vch_t *vch,char addr[36],int *outtype)
{
    struct sato_script_dest dest;
    if (wl_sato_script_extract_dest(vch,&dest) == 0)
    {
        uint8_t prefix = dest.outtype == TX_SCRIPTHASH ? SCRIPT_PREFIX : PUBKEY_PREFIX;
        *outtype = dest.outtype;
        return wl_sato_md20_address(prefix,&dest.id,addr,36);
    }
    return -1;
}

/* key & address funcionts */

int wl_btc_is_compressed()
{
    return PUBKEY_COMPRESSED;
}

int wl_btc_get_addr(const uint8_t *pubkey,char *addr,size_t len)
{
    return wl_sato_pubkey_address(PUBKEY_PREFIX,pubkey,(PUBKEY_COMPRESSED ? 33 : 65),addr,len);
}

int wl_btc_get_priv(const uint8_t *secret,vch_t *privkey)
{
    char encoded[64];
    uint8_t data[34] = {PRIVKEY_PREFIX,};
    memcpy(&data[1],secret,32);
    data[33] = 0x01;
    if (wl_base58_checkencode(data,34,encoded,64) == 0)
    {        
        wl_vch_clear(privkey);
        return wl_vch_push_string(privkey,encoded);
    }
    return -1;
}

int wl_btc_set_priv(const char *privkey,uint8_t *secret)
{
    uint8_t data[34];
    size_t len = 34;
    if (wl_base58_checkdecode(privkey,data,&len) == 0
        && data[0] == PRIVKEY_PREFIX && len == 34 && data[33] == 1)
    {
        memcpy(secret,&data[1],32);
        return 0;
    }
    return -1;
}

/* script funcionts */

static int wl_btc_script_push_pubkey(vch_t *script,const char *pubkey)
{
    int ret = -1;
    vch_t *vch = NULL;
    if (pubkey != NULL && (vch = wl_vch_new_hex(pubkey)) != NULL
        && (wl_vch_len(vch) == 33 || wl_vch_len(vch) == 65))
    {
        ret = wl_sato_script_push_data(script,vch);
    }
    wl_vch_free(vch);
    return ret;
}

static int wl_btc_build_script_multisig(json_t *json,vch_t *script)
{
    size_t req,count = 0;
    json_t *jreq = wl_json_find(json,"req");
    json_t *jpubkeys = wl_json_find(json,"pubkeys");
    json_t *j;
    if (jreq == NULL || jpubkeys == NULL
        || (req = wl_json_get_integer(jreq)) <= 0 
        || (j = wl_json_array_first(jpubkeys)) == NULL)
    {
        return -1;
    }
    
    wl_vch_clear(script);
    if (wl_vch_push_uchar(script,OP_1 + (req - 1)) < 0)
    {
        return -1;
    }
    
    while (j != NULL)
    {
        if (wl_btc_script_push_pubkey(script,wl_json_get_string(j)) < 0)
        {
            return -1;
        }
        count++;
        j = wl_json_array_next(j);
    }

    if (count < req || wl_vch_push_uchar(script,OP_1 + (count - 1)) < 0)
    {
        return -1;
    }
    if (wl_vch_push_uchar(script,OP_CHECKMULTISIG) < 0)
    {
        return -1;
    }
    return 0;
}

int wl_btc_build_script(const char *context,vch_t *script,vch_t *scriptid)
{
    int ret = -1;
    json_t *json = wl_json_fromstring(context);
    if (json != NULL)
    {
        if (wl_json_is_object(json))
        {
            char *type = NULL;
            json_t *jtype = wl_json_find(json,"type");
            json_t *jparam = wl_json_find(json,"param");
            if (jtype != NULL && jparam != NULL && wl_json_is_object(jparam)
                && (type = wl_json_get_string(jtype)) != NULL)
            {
                if (strcmp(type,"multisig") == 0)
                {
                    ret = wl_btc_build_script_multisig(jparam,script);
                }
            }
        }
        wl_json_free(json);
    } 
    if (ret == 0)
    {
        char addr[36];
        if ((ret = wl_sato_script_address(SCRIPT_PREFIX,script,addr,36)) == 0)
        {
            wl_vch_clear(scriptid);
            ret = wl_vch_push_string(scriptid,addr);    
        }
    }
    return ret;
}

/* transaction funcionts */

struct btc_tx_input
{
    uint256_t txid;
    uint32_t n;
    uint32_t seq;
    vch_t *script_sig;
    vch_t *script_pk;
    vch_t *redeem;
    char address[36];
    int outtype;
};

struct btc_tx_output
{
    uint64_t value;
    vch_t *script_pk;
    char address[36];
};

struct btc_transaction
{
    uint32_t version;
    uint32_t locktime;
    size_t vin_count;
    size_t vout_count;
    struct btc_tx_input* vin;
    struct btc_tx_output* vout;
};

static void wl_btc_tx_init(struct btc_transaction *tx)
{
    memset(tx,0,sizeof(struct btc_transaction));
}

static void wl_btc_tx_clear(struct btc_transaction *tx)
{
    int i;
    tx->version = 0;
    tx->locktime = 0;
    if (tx->vin != NULL)
    {
        for (i = 0;i < tx->vin_count;i++)
        {
            wl_vch_free(tx->vin[i].script_sig);
            wl_vch_free(tx->vin[i].script_pk);
            wl_vch_free(tx->vin[i].redeem);
        }
        free(tx->vin);
        tx->vin = NULL;
    }
    if (tx->vout != NULL)
    {
        for (i = 0;i < tx->vout_count;i++)
        {
            wl_vch_free(tx->vout[i].script_pk);
        }
        free(tx->vout);
        tx->vout = NULL;
    }
    tx->vin_count = 0;
    tx->vout_count = 0;
}

static int wl_btc_txin_unserialize(buff_t *buf,const char *prevout,struct btc_tx_input *in)
{
    size_t len;
    if ((in->script_sig = wl_vch_new()) == NULL 
         || (in->script_pk = wl_vch_new_hex(prevout)) == NULL
         || (in->redeem = wl_vch_new()) == NULL)
    {
        return -1;
    }
    if (wl_buff_pop_bytes(buf,(uint8_t*)&in->txid,sizeof(uint256_t)) < 0)
    {
        return -1;
    }
    if (wl_buff_pop32(buf,&in->n) < 0)
    {
        return -1;
    }
    if (wl_buff_pop_varint(buf,&len) < 0 || wl_vch_resize(in->script_sig,len) < 0)
    {
        return -1;
    }
    if (wl_buff_pop_bytes(buf,wl_vch_data(in->script_sig),len) < 0)
    {
        return -1;
    }
    if (wl_buff_pop32(buf,&in->seq) < 0)
    {
        return -1;
    }

    if (wl_btc_extract_address(in->script_pk,in->address,&in->outtype) < 0)
    {
        return -1;
    }
    if (in->outtype == TX_SCRIPTHASH)
    {
        wl_script_export(WALLEVE_COINS_BTC,in->address,in->redeem);
    }
    return 0;
}

static int wl_btc_txout_unserialize(buff_t *buf,struct btc_tx_output *out)
{
    size_t len;
    int outtype;
    if ((out->script_pk = wl_vch_new()) == NULL)
    {
        return -1;
    }
    if (wl_buff_pop64(buf,&out->value) < 0)
    {
        return -1;
    }
    if (wl_buff_pop_varint(buf,&len) < 0 || wl_vch_resize(out->script_pk,len) < 0)
    {
        return -1;
    }

    if (wl_buff_pop_bytes(buf,wl_vch_data(out->script_pk),len) < 0)
    {
        return -1;
    }
    if (wl_btc_extract_address(out->script_pk,out->address,&outtype) < 0)
    {
        return -1;
    }
    return 0;
}

static int wl_btc_tx_unserialize(buff_t* buf,const char *context,struct btc_transaction *tx)
{
    int i;
    json_t *json,*jinpk;

    wl_btc_tx_clear(tx);

    if (wl_buff_pop32(buf,&tx->version) < 0)
    {
        return -1;
    }

    if ((json = wl_json_fromstring(context)) == NULL)
    {
        return -1;
    }

    if (wl_buff_pop_varint(buf,&tx->vin_count) < 0)
    {
        wl_json_free(json);
        return -1;
    }

    if (tx->vin_count > 0)
    {
        tx->vin = (struct btc_tx_input*)calloc(sizeof(struct btc_tx_input),tx->vin_count);
        if (tx->vin == NULL || (jinpk = wl_json_array_first(json)) == NULL)
        {
            wl_json_free(json);
            return -1;
        }
        for (i = 0;i < tx->vin_count;i++)
        {
            if (jinpk == NULL || !wl_json_is_string(jinpk))
            {
                wl_json_free(json);
                return -1;
            }
            if (wl_btc_txin_unserialize(buf,wl_json_get_string(jinpk),&tx->vin[i]) < 0)
            {
                wl_json_free(json);
                return -1;
            }
            jinpk = wl_json_array_next(jinpk);
        }
    }
    wl_json_free(json);
    
    if (wl_buff_pop_varint(buf,&tx->vout_count) < 0)
    {
        return -1;
    }

    if (tx->vout_count > 0)
    {
        tx->vout = (struct btc_tx_output*)calloc(sizeof(struct btc_tx_output),tx->vout_count);
        if (tx->vout == NULL)
        {
            return -1;
        }
        for (i = 0;i < tx->vout_count;i++)
        {
            if (wl_btc_txout_unserialize(buf,&tx->vout[i]) < 0)
            {
                return -1;
            }
        }
    }

    if (wl_buff_pop32(buf,&tx->locktime) < 0)
    {
        return -1;
    }
    return 0;
}

static int wl_btc_txin_serialize(buff_t* buf,struct btc_tx_input *in,vch_t *script)
{
    size_t len = (script != NULL ? wl_vch_len(script) : 0);
    if (wl_buff_push_bytes(buf,(uint8_t*)&in->txid,sizeof(uint256_t)) < 0)
    {
        return -1;
    }
    if (wl_buff_push32(buf,in->n) < 0)
    {
        return -1;
    }
    if (wl_buff_push_varint(buf,len) < 0)
    {
        return -1;
    }
    if (len != 0 && wl_buff_push_bytes(buf,wl_vch_data(script),len) < 0)
    {
        return -1;
    }
    if (wl_buff_push32(buf,(script != NULL ? in->seq : 0)) < 0)
    {
        return -1;
    }
    return 0;
}

static int wl_btc_txout_serialize(buff_t* buf,struct btc_tx_output *out)
{
    if (wl_buff_push64(buf,out->value) < 0)
    {
        return -1;
    }
    if (wl_buff_push_varint(buf,wl_vch_len(out->script_pk)) < 0)
    {
        return -1;
    }
    if (wl_buff_push_bytes(buf,wl_vch_data(out->script_pk),wl_vch_len(out->script_pk)) < 0)
    {
        return -1;
    }
    return 0;
}

static int wl_btc_tx_serialize(buff_t* buf,struct btc_transaction *tx,int index)
{
    int i;
    wl_buff_clear(buf);
    if (wl_buff_push32(buf,tx->version) < 0)
    {
        return -1;
    }

    if (wl_buff_push_varint(buf,tx->vin_count) < 0)
    {
        return -1;
    }

    for (i = 0;i < tx->vin_count;i++)
    {
        vch_t *script = NULL;
        if (index < 0)
        {
            script = tx->vin[i].script_sig;
        }
        else if (index == i)
        {
            script = tx->vin[i].outtype == TX_SCRIPTHASH 
                     ? tx->vin[i].redeem : tx->vin[i].script_pk;
        }
        if (wl_btc_txin_serialize(buf,&tx->vin[i],script) < 0)
        {
            return -1;
        }
    }

    if (wl_buff_push_varint(buf,tx->vout_count) < 0)
    {
        return -1;
    }

    for (i = 0;i < tx->vout_count;i++)
    {
        if (wl_btc_txout_serialize(buf,&tx->vout[i]) < 0)
        {
            return -1;
        }
    }

    if (wl_buff_push32(buf,tx->locktime) < 0)
    {
        return -1;
    }
    return 0;
}

static inline int wl_btc_tx_hash(struct btc_transaction *tx,int index,uint256_t *hash)
{
    buff_t buf;
    if (wl_buff_init(&buf) < 0 || wl_btc_tx_serialize(&buf,tx,index) < 0)
    {
        wl_buff_deinit(&buf);
        return -1;
    }
    if (index >= 0 && wl_buff_push32(&buf,SIGHASH_ALL) < 0)
    {
        wl_buff_deinit(&buf);
        return -1;
    }
    wl_hash256d(wl_vch_data(buf.vch),wl_vch_len(buf.vch),hash);

    wl_buff_deinit(&buf);
    return 0;
}

static inline int wl_btc_tx_serialize_hex(struct btc_transaction *tx,vch_t *vch)
{
    int ret = -1;
    buff_t buf;
    wl_vch_clear(vch);
    if (wl_buff_init(&buf) == 0 && wl_btc_tx_serialize(&buf,tx,-1) == 0
        && wl_vch_push_hex(vch,wl_vch_data(buf.vch),wl_vch_len(buf.vch)) == 0)
    {
        ret = 0;
    }
    wl_buff_deinit(&buf);
    return ret;
}

static inline int wl_btc_tx_fromhex(const char *tx_data,const char *tx_ctxt,struct btc_transaction *tx)
{
    buff_t buf;
    int ret = -1;
    if (wl_buff_init_hex(&buf,tx_data) == 0 && tx_ctxt != NULL)
    {
        ret = wl_btc_tx_unserialize(&buf,tx_ctxt,tx);
    }
    wl_buff_deinit(&buf);
    return ret;
}

static int wl_btc_tx_json(struct btc_transaction* tx,json_t *json)
{
    int i;
    json_t *vin,*vout;
    if (wl_json_insert(json,wl_json_new_integer("version",tx->version)) == NULL)
    {
        return -1;
    }
    if (wl_json_insert(json,wl_json_new_integer("locktime",tx->locktime)) == NULL)
    {
        return -1;
    }
    if ((vin = wl_json_insert(json,wl_json_new("vin",WL_JSON_ARRAY))) == NULL)
    {
        return -1;
    }
    if ((vout = wl_json_insert(json,wl_json_new("vout",WL_JSON_ARRAY))) == NULL)
    {
        return -1;
    }
    for (i = 0;i < tx->vin_count;i++)
    {
        vch_t* txid;
        json_t *in;
        if ((in = wl_json_insert(vin,wl_json_new(NULL,WL_JSON_OBJECT))) == NULL)
        {
            return -1;
        }
        if ((txid = wl_vch_new()) == NULL)
        {
            return -1;
        }
        if (wl_vch_push_rhex(txid,(uint8_t*)&tx->vin[i].txid,sizeof(uint256_t)) < 0)
        {
            wl_vch_free(txid);
            return -1;
        }
        if (wl_json_insert(in,wl_json_new_string("txid",wl_vch_string(txid))) == NULL)
        {
            wl_vch_free(txid);
            return -1;
        }
        wl_vch_free(txid);

        if (wl_json_insert(in,wl_json_new_integer("output",tx->vin[i].n)) == NULL)
        {
            return -1;
        }
        if (wl_json_insert(in,wl_json_new_integer("sequence",tx->vin[i].seq)) == NULL)
        {
            return -1;
        }
        if (wl_json_insert(in,wl_json_new_string("address",tx->vin[i].address)) == NULL)
        {
            return -1;
        }
    }

    for (i = 0;i < tx->vout_count;i++)
    {
        json_t *out;
        if ((out = wl_json_insert(vout,wl_json_new(NULL,WL_JSON_OBJECT))) == NULL)
        {
            return -1;
        }
        if (wl_json_insert(out,wl_json_new_string("address",tx->vout[i].address)) == NULL)
        {
            return -1;
        }
        if (wl_json_insert(out,wl_json_new_float("amount",wl_btc_tocoin(tx->vout[i].value))) == NULL)
        {
            return -1;
        }
    }
    return 0;
}

static inline int wl_btc_sign_txin_pubkey(struct btc_tx_input* in,uint256_t hash,const char *addr)
{
    vch_t *sig = wl_vch_new(); 
    wl_vch_clear(in->script_sig);
    if (sig == NULL)
    {
        return -1;
    }
    if (wl_key_sign(WALLEVE_COINS_BTC,addr,hash.u8,sig) < 0
        || wl_vch_push_uchar(sig,SIGHASH_ALL) < 0
        || wl_sato_script_push_data(in->script_sig,sig) < 0)
    {
        wl_vch_free(sig);
        return -1;
    }
    wl_vch_free(sig);
    return 0;
}

static inline int wl_btc_sign_txin_pubkeyhash(struct btc_tx_input* in,uint256_t hash,const char *addr)
{
    vch_t *pkdata = NULL;
    if (wl_btc_sign_txin_pubkey(in,hash,addr) < 0)
    {
        return -1;
    }
    if ((pkdata = wl_vch_new()) == NULL 
        || wl_key_pkdata(WALLEVE_COINS_BTC,addr,pkdata) < 0
        || wl_sato_script_push_data(in->script_sig,pkdata) < 0)
    {
        wl_vch_free(pkdata);
        return -1;
    }
    wl_vch_free(pkdata);
    return 0;
}

static inline int wl_btc_sign_txin_multisig(struct btc_tx_input* in,uint256_t hash,
                                            struct sato_multisig_ctxt *multisig)
{
    vch_t *sig[multisig->count];
    int signedkey,mysigned = 0;
    int i,ret = -1;
    for (i = 0; i < multisig->count;i++)
    {
        if ((sig[i] = wl_vch_new()) == NULL)
        {            
            while (i-- > 0)
            {
                wl_vch_free(sig[i]);
            }
            return -1;
        }
    } 
    signedkey = wl_sato_script_validate_multisig(multisig,&hash,in->redeem,in->script_sig,sig);
    if (signedkey < 0)
    {
        signedkey = 0;
    }
    
    for (i = 0;i < multisig->count && signedkey + mysigned < multisig->req;i++)
    {
        if (wl_vch_len(sig[i]) == 0)
        {
            char addr[36];
            if (wl_sato_pubkey_address(PUBKEY_PREFIX,multisig->pubkeys[i],
                                                     multisig->size[i],addr,36) == 0
                && wl_key_sign(WALLEVE_COINS_BTC,addr,hash.u8,sig[i]) == 0
                && wl_vch_push_uchar(sig[i],SIGHASH_ALL) == 0)
            {
                mysigned++;
            }
        }
    }
    if (mysigned > 0)
    {
        ret = wl_sato_script_combine_multisig(multisig,sig,in->script_sig);
    }
    for (i = 0;i < multisig->count;i++)
    {
        wl_vch_free(sig[i]);
    }
    return ret;
}

static int wl_btc_sign_txin_scripthash(struct btc_tx_input* in,uint256_t hash)
{
    struct sato_script_op op[18];
    size_t count = 18;
    struct sato_multisig_ctxt multisig;
    if ((wl_sato_script_parse_op(in->redeem,op,&count)) < 0)
    {
        return -1;
    }
    if (wl_sato_script_solver_multisig(op,count,&multisig) == 0)
    {
        if (wl_btc_sign_txin_multisig(in,hash,&multisig) == 0)
        {
            return wl_sato_script_push_data(in->script_sig,in->redeem);
        }
    }
    return -1;
}

static int wl_btc_sign_txin(struct btc_transaction *tx,size_t index)
{
    uint256_t hash = UINT256_ZERO;
    if (wl_btc_tx_hash(tx,index,&hash) < 0)
    {
        return -1;
    }
    
    if (tx->vin[index].outtype == TX_PUBKEY)
    {
        return wl_btc_sign_txin_pubkey(&tx->vin[index],hash,tx->vin[index].address);
    }
    else if (tx->vin[index].outtype == TX_PUBKEYHASH)
    {
        return wl_btc_sign_txin_pubkeyhash(&tx->vin[index],hash,tx->vin[index].address);
    }
    else if (tx->vin[index].outtype == TX_SCRIPTHASH)
    {
        return wl_btc_sign_txin_scripthash(&tx->vin[index],hash);
    }
    return -1;
}

static int wl_btc_verify_txin_json(json_t *json,const char *type,char addr[][36],size_t count)
{
    size_t i;
    json_t *jverify;
    if (wl_json_insert(json,wl_json_new_string("type",type)) == NULL
        || (jverify = wl_json_insert(json,wl_json_new("verified",WL_JSON_ARRAY))) == NULL)
    {
        return -1;
    }
    for (i = 0;i < count;i++)
    {
        if (wl_json_insert(jverify,wl_json_new_string(NULL,addr[i])) == NULL)
        {
            return -1;
        }
    }
    return 0;
}

static int wl_btc_verify_txin_multisig(uint256_t *hash,vch_t *redeem,vch_t *script_sig,
                                       struct sato_multisig_ctxt *multisig,char verified[3][36])
{
    vch_t *sig[multisig->count];
    int i,n = 0;

    for (i = 0; i < multisig->count;i++)
    {
        if ((sig[i] = wl_vch_new()) == NULL)
        {            
            while (i-- > 0)
            {
                wl_vch_free(sig[i]);
            }
            return -1;
        }
    } 

    wl_sato_script_validate_multisig(multisig,hash,redeem,script_sig,sig);
    
    for (i = 0;i < multisig->count;i++)
    {
        if (wl_vch_len(sig[i]) != 0)
        {
            if (wl_sato_pubkey_address(PUBKEY_PREFIX,multisig->pubkeys[i],
                                                     multisig->size[i],verified[n],36) == 0)
            {
                n++;
            }
        }
        wl_vch_free(sig[i]);
    }
    return n;
}

static int wl_btc_verify_txin_redeem(struct btc_tx_input* in,uint256_t hash,json_t *json)
{
    struct sato_script_op op[18];
    size_t count = 18;
    struct sato_multisig_ctxt multisig;

    if (wl_sato_script_validate_scripthash(in->script_pk,in->script_sig,in->redeem) < 0
        || wl_sato_script_parse_op(in->redeem,op,&count) < 0)
    {
        wl_btc_verify_txin_json(json,"scripthash",NULL,0);
        return -1;
    }
    if (wl_sato_script_solver_multisig(op,count,&multisig) == 0)
    {
        char verified[3][36];
        int n = wl_btc_verify_txin_multisig(&hash,in->redeem,in->script_sig,&multisig,verified);
        if (wl_btc_verify_txin_json(json,"multisig",verified,n < 0 ? 0 : n) == 0
            && n == multisig.req)
        {
            return 0;
        }
    }
    else
    {
        wl_btc_verify_txin_json(json,"scripthash",NULL,0);
    }
    return -1;
}

static int wl_btc_verify_txin(struct btc_transaction *tx,size_t index,json_t *json)
{
    uint256_t hash = UINT256_ZERO;
    if (wl_btc_tx_hash(tx,index,&hash) < 0)
    {
        return -1;
    }
    if (tx->vin[index].outtype == TX_PUBKEY)
    {
        if (wl_sato_script_validate_pubkey(&hash,tx->vin[index].script_pk,tx->vin[index].script_sig) == 0)
        {
            return wl_btc_verify_txin_json(json,"pubkey",&tx->vin[index].address,1);
        }
        wl_btc_verify_txin_json(json,"pubkey",NULL,0);
    }
    else if (tx->vin[index].outtype == TX_PUBKEYHASH)
    {
        if (wl_sato_script_validate_pubkeyhash(&hash,tx->vin[index].script_pk,tx->vin[index].script_sig) == 0)
        {
            return wl_btc_verify_txin_json(json,"pubkeyhash",&tx->vin[index].address,1);
        }
        wl_btc_verify_txin_json(json,"pubkeyhash",NULL,0);
    }
    else if (tx->vin[index].outtype == TX_SCRIPTHASH)
    {
        return wl_btc_verify_txin_redeem(&tx->vin[index],hash,json);
    }
    return -1;
}

int wl_btc_parse_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_json)
{
    json_t *json;
    struct btc_transaction tx;
    wl_btc_tx_init(&tx);
    if (wl_btc_tx_fromhex(tx_data,tx_ctxt,&tx) < 0)
    {
        wl_btc_tx_clear(&tx);
        return -1;
    }

    if ((json = wl_json_new(NULL,WL_JSON_OBJECT)) == NULL)
    {
        wl_btc_tx_clear(&tx);
        return -1;
    }

    if (wl_btc_tx_json(&tx,json) < 0 || wl_json_tostring(json,tx_json) < 0)
    {
        wl_json_free(json);
        wl_btc_tx_clear(&tx);
        return -1;
    }

    wl_json_free(json);
    wl_btc_tx_clear(&tx);

    return 0;
}

int wl_btc_sign_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_signed)
{
    int i;
    struct btc_transaction tx;
    wl_btc_tx_init(&tx);
    if (wl_btc_tx_fromhex(tx_data,tx_ctxt,&tx) < 0)
    {
        wl_btc_tx_clear(&tx);
        return -1;
    }

    for (i = 0;i < tx.vin_count;i++)
    {
        if (wl_btc_sign_txin(&tx,i) < 0)
        {
            wl_btc_tx_clear(&tx);
            return -1;
        }
    }
    
    if (wl_btc_tx_serialize_hex(&tx,tx_signed) < 0)
    {
        wl_btc_tx_clear(&tx);
        return -1;
    }
    wl_btc_tx_clear(&tx);
    return 0;
}

int wl_btc_verify_tx(const char *tx_data,const char *tx_ctxt,vch_t *ret_json)
{
    json_t *json,*jcomplt,*jvin;
    struct btc_transaction tx;
    size_t i;
    wl_btc_tx_init(&tx);
    if (wl_btc_tx_fromhex(tx_data,tx_ctxt,&tx) < 0)
    {
        wl_btc_tx_clear(&tx);
        return -1;
    }

    if ((json = wl_json_new(NULL,WL_JSON_OBJECT)) == NULL
        || (jcomplt = wl_json_insert(json,wl_json_new_boolean("completed",1))) == NULL
        || (jvin = wl_json_insert(json,wl_json_new("input",WL_JSON_ARRAY))) == NULL)
    {
        wl_btc_tx_clear(&tx);
        wl_json_free(json);
        return -1;
    }

    for (i = 0;i < tx.vin_count;i++)
    {
        json_t *jin;
        if ((jin = wl_json_insert(jvin,wl_json_new(NULL,WL_JSON_OBJECT))) == NULL
            || wl_json_insert(jin,wl_json_new_integer("n",i)) == NULL)
        {
            wl_btc_tx_clear(&tx);
            wl_json_free(json);
            return -1;
        }
        
        if (wl_btc_verify_txin(&tx,i,jin) < 0)
        {
            jcomplt->value.b = 0; 
        }
    }
    if (wl_json_tostring(json,ret_json) < 0)
    {
        wl_btc_tx_clear(&tx);
        wl_json_free(json);
        return -1;
    }
    wl_btc_tx_clear(&tx);
    wl_json_free(json);
    return 0;
}

