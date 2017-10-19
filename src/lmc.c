// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "lmc.h"
#include "biguint.h"
#include "buff.h"
#include "json.h"
#include "key.h"
#include "script.h"

#include "base58.h"
#include "crypto.h"
#include "sato.h"


#define OP_COINSTAKE 		0xc0

#define PUBKEY_COMPRESSED	1

enum
{
#if ! TESTNET
    PUBKEY_PREFIX = 48,  // lomocoin: addresses begin with 'L'
    SCRIPT_PREFIX = 125, // lomocoin: addresses begin with 's'
    PRIVKEY_PREFIX = PUBKEY_PREFIX + 128,
#else
    PUBKEY_PREFIX = 111,
    SCRIPT_PREFIX = 196,
    PRIVKEY_PREFIX = PUBKEY_PREFIX + 128,
#endif
};

static inline double wl_lmc_tocoin(uint64_t value)
{
    return (((double)value) / 1000000.0);
}

static inline int wl_lmc_extract_address(vch_t *vch,char addr[36],int *outtype)
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

int wl_lmc_is_compressed()
{
    return PUBKEY_COMPRESSED;
}

int wl_lmc_get_addr(const uint8_t *pubkey,char *addr,size_t len)
{
    return wl_sato_pubkey_address(PUBKEY_PREFIX,pubkey,(PUBKEY_COMPRESSED ? 33 : 65),addr,len);
}

int wl_lmc_get_priv(const uint8_t *secret,vch_t *privkey)
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

int wl_lmc_set_priv(const char *privkey,uint8_t *secret)
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

static int wl_lmc_script_push_pubkey(vch_t *script,const char *pubkey)
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

static int wl_lmc_build_script_multisig(json_t *json,vch_t *script)
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
        if (wl_lmc_script_push_pubkey(script,wl_json_get_string(j)) < 0)
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

static int wl_lmc_build_script_coldminting(json_t *json,vch_t *script)
{
    char *mint,*spent;
    uint8_t data[21],id[21];
    size_t data_len = 21;
    size_t id_len = 21;
    json_t *jmint = wl_json_find(json,"mint");
    json_t *jspent = wl_json_find(json,"spent");
    if (jmint == NULL || jspent == NULL
        || (mint = wl_json_get_string(jmint)) == NULL
        || (spent = wl_json_get_string(jspent)) == NULL)
    {
        return -1;
    }

    if (wl_base58_checkdecode(mint,data,&data_len) < 0
        || wl_base58_checkdecode(spent,id,&id_len) < 0)
    {
        return -1;
    }
    
    wl_vch_clear(script);
    if (id[0] == PUBKEY_PREFIX)
    {
        uint8_t op1[5] = {OP_DUP,OP_HASH160,OP_COINSTAKE,OP_IF,20};
        uint8_t op2[2] = {OP_ELSE,20};
        uint8_t op3[3] = {OP_ENDIF,OP_EQUALVERIFY,OP_CHECKSIG};
        if (wl_vch_push(script,op1,5) == 0
            && wl_vch_push(script,&data[1],20) == 0
            && wl_vch_push(script,op2,2) == 0
            && wl_vch_push(script,&id[1],20) == 0
            && wl_vch_push(script,op3,3) == 0)
        {
            return 0;
        }
    }
    else if (id[0] == SCRIPT_PREFIX)
    {
        vch_t *inner = wl_vch_new();
        if (inner != NULL)
        {
            uint8_t op1[5] = {OP_COINSTAKE,OP_IF,OP_DUP,OP_HASH160,20};
            uint8_t op2[3] = {OP_EQUALVERIFY,OP_CHECKSIG,OP_ELSE};
            if (wl_script_export(WALLEVE_COINS_LMC,spent,inner) == 0)
            {
                if (wl_vch_push(script,op1,5) == 0
                    && wl_vch_push(script,&data[1],20) == 0
                    && wl_vch_push(script,op2,3) == 0
                    && wl_vch_push(script,wl_vch_data(inner),wl_vch_len(inner)) == 0
                    && wl_vch_push_uchar(script,OP_ENDIF) == 0)
                {
                    wl_vch_free(inner);
                    return 0;
                }
            }
            wl_vch_free(inner);
        }
    }
    return -1;
}

static int wl_lmc_script_solver_coldminting(struct sato_script_op *op,size_t n,
                                            char mint[36],char spent[36])
{
    const uint8_t opt[] = {OP_DUP,OP_HASH160,OP_COINSTAKE,OP_IF,OP_PUBKEYHASH,OP_ELSE,
                                   OP_PUBKEYHASH,OP_ENDIF,OP_EQUALVERIFY,OP_CHECKSIG};

    if (wl_sato_script_match_template(op,n,opt,sizeof(opt)) == 0)
    {
        if (wl_sato_md20_address(PUBKEY_PREFIX,op[4].data,mint,36) < 0
            || wl_sato_md20_address(PUBKEY_PREFIX,op[6].data,spent,36) < 0)
        {
            return -1;
        }
        return 0;
    }
    return -1;
}

static int wl_lmc_script_solver_multisigcoldminting(struct sato_script_op *op,size_t n,
                                                    char mint[36],struct sato_multisig_ctxt *multisig)
{
    const uint8_t opt[] = {OP_COINSTAKE,OP_IF,OP_DUP,OP_HASH160,OP_PUBKEYHASH,OP_EQUALVERIFY,
                           OP_CHECKSIG,OP_ELSE,OP_SMALLINTEGER,OP_PUBKEYS,OP_SMALLINTEGER,
                           OP_CHECKMULTISIG,OP_ENDIF}; 

    if (wl_sato_script_match_template(op,n,opt,sizeof(opt)) == 0 
        && n == op[n - 3].opcode - OP_1 + 1 + 12)
    {
        if (wl_sato_md20_address(PUBKEY_PREFIX,op[4].data,mint,36) < 0)
        {
            return -1;
        }
        return wl_sato_script_solver_multisig(op + 8,n - 9,multisig);
    }
    return -1;
}

int wl_lmc_build_script(const char *context,vch_t *script,vch_t *scriptid)
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
                    ret = wl_lmc_build_script_multisig(jparam,script);
                }
                else if (strcmp(type,"coldminting") == 0)
                {
                    ret = wl_lmc_build_script_coldminting(jparam,script);
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

struct lmc_tx_input
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

struct lmc_tx_output
{
    uint64_t value;
    vch_t *script_pk;
    char address[36];
};

struct lmc_transaction
{
    uint32_t version;
    uint32_t timestamp;
    uint32_t locktime;
    size_t vin_count;
    size_t vout_count;
    struct lmc_tx_input* vin;
    struct lmc_tx_output* vout;
};

static void wl_lmc_tx_init(struct lmc_transaction *tx)
{
    memset(tx,0,sizeof(struct lmc_transaction));
}

static void wl_lmc_tx_clear(struct lmc_transaction *tx)
{
    int i;
    tx->version = 0;
    tx->timestamp = 0;
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

static int wl_lmc_txin_unserialize(buff_t *buf,const char *prevout,struct lmc_tx_input *in)
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

    if (wl_lmc_extract_address(in->script_pk,in->address,&in->outtype) < 0)
    {
        return -1;
    }
    if (in->outtype == TX_SCRIPTHASH)
    {
        wl_script_export(WALLEVE_COINS_LMC,in->address,in->redeem);
    }
    return 0;
}

static int wl_lmc_txout_unserialize(buff_t *buf,struct lmc_tx_output *out)
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
    if (wl_lmc_extract_address(out->script_pk,out->address,&outtype) < 0)
    {
        return -1;
    }
    return 0;
}

static int wl_lmc_tx_unserialize(buff_t* buf,const char *context,struct lmc_transaction *tx)
{
    int i;
    json_t *json,*jinpk;

    wl_lmc_tx_clear(tx);

    if (wl_buff_pop32(buf,&tx->version) < 0)
    {
        return -1;
    }

    if (wl_buff_pop32(buf,&tx->timestamp) < 0)
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
        tx->vin = (struct lmc_tx_input*)calloc(sizeof(struct lmc_tx_input),tx->vin_count);
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
            if (wl_lmc_txin_unserialize(buf,wl_json_get_string(jinpk),&tx->vin[i]) < 0)
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
        tx->vout = (struct lmc_tx_output*)calloc(sizeof(struct lmc_tx_output),tx->vout_count);
        if (tx->vout == NULL)
        {
            return -1;
        }
        for (i = 0;i < tx->vout_count;i++)
        {
            if (wl_lmc_txout_unserialize(buf,&tx->vout[i]) < 0)
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

static int wl_lmc_txin_serialize(buff_t* buf,struct lmc_tx_input *in,vch_t *script)
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

static int wl_lmc_txout_serialize(buff_t* buf,struct lmc_tx_output *out)
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

static int wl_lmc_tx_serialize(buff_t* buf,struct lmc_transaction *tx,int index)
{
    int i;
    wl_buff_clear(buf);
    if (wl_buff_push32(buf,tx->version) < 0)
    {
        return -1;
    }

    if (wl_buff_push32(buf,tx->timestamp) < 0)
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
        if (wl_lmc_txin_serialize(buf,&tx->vin[i],script) < 0)
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
        if (wl_lmc_txout_serialize(buf,&tx->vout[i]) < 0)
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

static inline int wl_lmc_tx_hash(struct lmc_transaction *tx,int index,uint256_t *hash)
{
    buff_t buf;
    if (wl_buff_init(&buf) < 0 || wl_lmc_tx_serialize(&buf,tx,index) < 0)
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

static inline int wl_lmc_tx_serialize_hex(struct lmc_transaction *tx,vch_t *vch)
{
    int ret = -1;
    buff_t buf;
    wl_vch_clear(vch);
    if (wl_buff_init(&buf) == 0 && wl_lmc_tx_serialize(&buf,tx,-1) == 0
        && wl_vch_push_hex(vch,wl_vch_data(buf.vch),wl_vch_len(buf.vch)) == 0)
    {
        ret = 0;
    }
    wl_buff_deinit(&buf);
    return ret;
}

static inline int wl_lmc_tx_fromhex(const char *tx_data,const char *tx_ctxt,struct lmc_transaction *tx)
{
    buff_t buf;
    int ret = -1;
    if (wl_buff_init_hex(&buf,tx_data) == 0 && tx_ctxt != NULL)
    {
        ret = wl_lmc_tx_unserialize(&buf,tx_ctxt,tx);
    }
    wl_buff_deinit(&buf);
    return ret;
}

static int wl_lmc_tx_json(struct lmc_transaction* tx,json_t *json)
{
    int i;
    json_t *vin,*vout;
    if (wl_json_insert(json,wl_json_new_integer("version",tx->version)) == NULL)
    {
        return -1;
    }
    if (wl_json_insert(json,wl_json_new_integer("timestamp",tx->timestamp)) == NULL)
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
        if (wl_json_insert(out,wl_json_new_float("amount",wl_lmc_tocoin(tx->vout[i].value))) == NULL)
        {
            return -1;
        }
    }
    return 0;
}

static inline int wl_lmc_sign_txin_pubkey(struct lmc_tx_input* in,uint256_t hash,const char *addr)
{
    vch_t *sig = wl_vch_new(); 
    wl_vch_clear(in->script_sig);
    if (sig == NULL)
    {
        return -1;
    }
    if (wl_key_sign(WALLEVE_COINS_LMC,addr,hash.u8,sig) < 0
        || wl_vch_push_uchar(sig,SIGHASH_ALL) < 0
        || wl_sato_script_push_data(in->script_sig,sig) < 0)
    {
        wl_vch_free(sig);
        return -1;
    }
    wl_vch_free(sig);
    return 0;
}

static inline int wl_lmc_sign_txin_pubkeyhash(struct lmc_tx_input* in,uint256_t hash,const char *addr)
{
    vch_t *pkdata = NULL;
    if (wl_lmc_sign_txin_pubkey(in,hash,addr) < 0)
    {
        return -1;
    }
    if ((pkdata = wl_vch_new()) == NULL 
        || wl_key_pkdata(WALLEVE_COINS_LMC,addr,pkdata) < 0
        || wl_sato_script_push_data(in->script_sig,pkdata) < 0)
    {
        wl_vch_free(pkdata);
        return -1;
    }
    wl_vch_free(pkdata);
    return 0;
}

static inline int wl_lmc_sign_txin_multisig(struct lmc_tx_input* in,uint256_t hash,
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
                && wl_key_sign(WALLEVE_COINS_LMC,addr,hash.u8,sig[i]) == 0
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

static int wl_lmc_sign_txin_scripthash(struct lmc_tx_input* in,uint256_t hash)
{
    struct sato_script_op op[18];
    size_t count = 18;
    char mint[36],spent[36];
    struct sato_multisig_ctxt multisig;
    if ((wl_sato_script_parse_op(in->redeem,op,&count)) < 0)
    {
        return -1;
    }
    if (wl_sato_script_solver_multisig(op,count,&multisig) == 0
        || wl_lmc_script_solver_multisigcoldminting(op,count,mint,&multisig) == 0)
    {
        if (wl_lmc_sign_txin_multisig(in,hash,&multisig) == 0)
        {
            return wl_sato_script_push_data(in->script_sig,in->redeem);
        }
    }
    else if (wl_lmc_script_solver_coldminting(op,count,mint,spent) == 0)
    {
        if (wl_lmc_sign_txin_pubkeyhash(in,hash,spent) == 0)
        {
            return wl_sato_script_push_data(in->script_sig,in->redeem);
        }
    }
    return -1;
}

static int wl_lmc_sign_txin(struct lmc_transaction *tx,size_t index)
{
    uint256_t hash = UINT256_ZERO;
    if (wl_lmc_tx_hash(tx,index,&hash) < 0)
    {
        return -1;
    }
    
    if (tx->vin[index].outtype == TX_PUBKEY)
    {
        return wl_lmc_sign_txin_pubkey(&tx->vin[index],hash,tx->vin[index].address);
    }
    else if (tx->vin[index].outtype == TX_PUBKEYHASH)
    {
        return wl_lmc_sign_txin_pubkeyhash(&tx->vin[index],hash,tx->vin[index].address);
    }
    else if (tx->vin[index].outtype == TX_SCRIPTHASH)
    {
        return wl_lmc_sign_txin_scripthash(&tx->vin[index],hash);
    }
    return -1;
}

static int wl_lmc_verify_txin_json(json_t *json,const char *type,char addr[][36],size_t count)
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

static int wl_lmc_verify_txin_coldminting(uint256_t *hash,vch_t *script_sig,const char *spent)
{
    char addr[36];
    struct sato_script_op op[3];
    size_t n = 3;

    if (script_sig != NULL && spent != NULL
        && wl_sato_script_parse_op(script_sig,op,&n) == 0 && n == 3
        && op[0].data != NULL && op[0].size > 1
        && op[1].data != NULL && (op[1].size == 33 || op[1].size == 65)
        && op[2].data != NULL && op[2].size > 1
        && wl_sato_pubkey_address(PUBKEY_PREFIX,op[1].data,op[1].size,addr,36) == 0)
    {
        int compress = op[1].size == 33 ? 1 : 0;
        if (strcmp(addr,spent) == 0) 
        {
            return wl_secp_verify_signature(op[1].data,compress,hash,op[0].data,op[0].size - 1);
        }
    }
    return -1;
}

static int wl_lmc_verify_txin_multisig(uint256_t *hash,vch_t *redeem,vch_t *script_sig,
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

static int wl_lmc_verify_txin_redeem(struct lmc_tx_input* in,uint256_t hash,json_t *json)
{
    struct sato_script_op op[18];
    size_t count = 18;
    char mint[36],spent[36];
    struct sato_multisig_ctxt multisig;

    if (wl_sato_script_validate_scripthash(in->script_pk,in->script_sig,in->redeem) < 0
        || wl_sato_script_parse_op(in->redeem,op,&count) < 0)
    {
        wl_lmc_verify_txin_json(json,"scripthash",NULL,0);
        return -1;
    }
    if (wl_sato_script_solver_multisig(op,count,&multisig) == 0)
    {
        char verified[3][36];
        int n = wl_lmc_verify_txin_multisig(&hash,in->redeem,in->script_sig,&multisig,verified);
        if (wl_lmc_verify_txin_json(json,"multisig",verified,n < 0 ? 0 : n) == 0
            && n == multisig.req)
        {
            return 0;
        }
    }
    else if (wl_lmc_script_solver_multisigcoldminting(op,count,mint,&multisig) == 0)
    {
        char verified[3][36];
        int n = wl_lmc_verify_txin_multisig(&hash,in->redeem,in->script_sig,&multisig,verified);
        if (wl_lmc_verify_txin_json(json,"multisigcoldminting",verified,n < 0 ? 0 : n) == 0
            && n == multisig.req)
        {
            return 0;
        }
    }
    else if (wl_lmc_script_solver_coldminting(op,count,mint,spent) == 0)
    {
        if (wl_lmc_verify_txin_coldminting(&hash,in->script_sig,spent) == 0)
        {
            return wl_lmc_verify_txin_json(json,"coldminting",&spent,1);
        }
        wl_lmc_verify_txin_json(json,"coldminting",NULL,0);
    }
    else
    {
        wl_lmc_verify_txin_json(json,"scripthash",NULL,0);
    }
    return -1;
}

static int wl_lmc_verify_txin(struct lmc_transaction *tx,size_t index,json_t *json)
{
    uint256_t hash = UINT256_ZERO;
    if (wl_lmc_tx_hash(tx,index,&hash) < 0)
    {
        return -1;
    }
    if (tx->vin[index].outtype == TX_PUBKEY)
    {
        if (wl_sato_script_validate_pubkey(&hash,tx->vin[index].script_pk,tx->vin[index].script_sig) == 0)
        {
            return wl_lmc_verify_txin_json(json,"pubkey",&tx->vin[index].address,1);
        }
        wl_lmc_verify_txin_json(json,"pubkey",NULL,0);
    }
    else if (tx->vin[index].outtype == TX_PUBKEYHASH)
    {
        if (wl_sato_script_validate_pubkeyhash(&hash,tx->vin[index].script_pk,tx->vin[index].script_sig) == 0)
        {
            return wl_lmc_verify_txin_json(json,"pubkeyhash",&tx->vin[index].address,1);
        }
        wl_lmc_verify_txin_json(json,"pubkeyhash",NULL,0);
    }
    else if (tx->vin[index].outtype == TX_SCRIPTHASH)
    {
        return wl_lmc_verify_txin_redeem(&tx->vin[index],hash,json);
    }
    return -1;
}

int wl_lmc_parse_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_json)
{
    json_t *json;
    struct lmc_transaction tx;
    wl_lmc_tx_init(&tx);
    if (wl_lmc_tx_fromhex(tx_data,tx_ctxt,&tx) < 0)
    {
        wl_lmc_tx_clear(&tx);
        return -1;
    }

    if ((json = wl_json_new(NULL,WL_JSON_OBJECT)) == NULL)
    {
        wl_lmc_tx_clear(&tx);
        return -1;
    }

    if (wl_lmc_tx_json(&tx,json) < 0 || wl_json_tostring(json,tx_json) < 0)
    {
        wl_json_free(json);
        wl_lmc_tx_clear(&tx);
        return -1;
    }

    wl_json_free(json);
    wl_lmc_tx_clear(&tx);

    return 0;
}

int wl_lmc_sign_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_signed)
{
    int i;
    struct lmc_transaction tx;
    wl_lmc_tx_init(&tx);
    if (wl_lmc_tx_fromhex(tx_data,tx_ctxt,&tx) < 0)
    {
        wl_lmc_tx_clear(&tx);
        return -1;
    }

    for (i = 0;i < tx.vin_count;i++)
    {
        if (wl_lmc_sign_txin(&tx,i) < 0)
        {
            wl_lmc_tx_clear(&tx);
            return -1;
        }
    }
    
    if (wl_lmc_tx_serialize_hex(&tx,tx_signed) < 0)
    {
        wl_lmc_tx_clear(&tx);
        return -1;
    }
    wl_lmc_tx_clear(&tx);
    return 0;
}

int wl_lmc_verify_tx(const char *tx_data,const char *tx_ctxt,vch_t *ret_json)
{
    json_t *json,*jcomplt,*jvin;
    struct lmc_transaction tx;
    size_t i;
    wl_lmc_tx_init(&tx);
    if (wl_lmc_tx_fromhex(tx_data,tx_ctxt,&tx) < 0)
    {
        wl_lmc_tx_clear(&tx);
        return -1;
    }

    if ((json = wl_json_new(NULL,WL_JSON_OBJECT)) == NULL
        || (jcomplt = wl_json_insert(json,wl_json_new_boolean("completed",1))) == NULL
        || (jvin = wl_json_insert(json,wl_json_new("input",WL_JSON_ARRAY))) == NULL)
    {
        wl_lmc_tx_clear(&tx);
        wl_json_free(json);
        return -1;
    }

    for (i = 0;i < tx.vin_count;i++)
    {
        json_t *jin;
        if ((jin = wl_json_insert(jvin,wl_json_new(NULL,WL_JSON_OBJECT))) == NULL
            || wl_json_insert(jin,wl_json_new_integer("n",i)) == NULL)
        {
            wl_lmc_tx_clear(&tx);
            wl_json_free(json);
            return -1;
        }
        
        if (wl_lmc_verify_txin(&tx,i,jin) < 0)
        {
            jcomplt->value.b = 0; 
        }
    }
    if (wl_json_tostring(json,ret_json) < 0)
    {
        wl_lmc_tx_clear(&tx);
        wl_json_free(json);
        return -1;
    }
    wl_lmc_tx_clear(&tx);
    wl_json_free(json);
    return 0;
}

