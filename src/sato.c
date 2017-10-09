// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sato.h"
#include "crypto.h"
#include "base58.h"

int wl_sato_md20_address(uint8_t prefix,void *md20,char *addr,size_t len)
{
    uint8_t data[21] = {prefix,};
    if (md20 != NULL && addr != NULL)
    {
        memcpy(&data[1],md20,20);
        return wl_base58_checkencode(data,sizeof(data),addr,len);
    }
    return -1;
}

int wl_sato_pubkey_address(uint8_t prefix,const uint8_t *pubkey,size_t size,char *addr,size_t len)
{
    uint8_t data[21] = {prefix,};
    if (pubkey != NULL && addr != NULL && (size == 33 || size == 65))
    {
        wl_hash160(pubkey,size,&data[1]);
        return wl_base58_checkencode(data,sizeof(data),addr,len);
    }
    return -1;
}

int wl_sato_script_address(uint8_t prefix,vch_t *script,char *addr,size_t len)
{
    uint8_t data[21] = {prefix,};
    if (script != NULL || addr != NULL)
    {
        wl_hash160(wl_vch_data(script),wl_vch_len(script),&data[1]);
        return wl_base58_checkencode(data,sizeof(data),addr,len);
    }
    return -1;
}

int wl_sato_script_push_opcode(vch_t *script,uint8_t opcode)
{
    return wl_vch_push_uchar(script,opcode);
}

int wl_sato_script_push_number(vch_t *script,uint8_t number)
{
    if (number == 0)
    {
        return wl_vch_push_uchar(script,OP_0);
    }
    else if (number <= 16)
    {
        return wl_vch_push_uchar(script,number - 1 + OP_1);
    }
    return -1;
}

static inline int wl_sato_script_push_datalen(vch_t *script,size_t len)
{
    if (len < OP_PUSHDATA1)
    {
        if (wl_vch_push_uchar(script,len) < 0)
        {
            return -1;
        }
    }
    else if (len <= 0xff)
    {
        if (wl_vch_push_uchar(script,OP_PUSHDATA1) < 0
            || wl_vch_push_uchar(script,len) < 0)
        {
            return -1;
        }
    }
    else if (len <= 0xffff)
    {
        if (wl_vch_push_uchar(script,OP_PUSHDATA2) < 0
            || wl_vch_push(script,(uint8_t*)&len,sizeof(uint16_t)) < 0)
        {
            return -1;
        }
    }
    else if (len <= 0xffffffff)
    {
        if (wl_vch_push_uchar(script,OP_PUSHDATA4) < 0
            || wl_vch_push(script,(uint8_t*)&len,sizeof(uint32_t)) < 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }
    return 0;
}

int wl_sato_script_push_data(vch_t *script,vch_t* vch)
{
    size_t len = wl_vch_len(vch);
    if (wl_sato_script_push_datalen(script,len) < 0)
    {
        return -1;
    }
    return wl_vch_cat(script,vch);
}

int wl_sato_script_push_bytes(vch_t *script,uint8_t *bytes,size_t len)
{
    if (wl_sato_script_push_datalen(script,len) < 0)
    {
        return -1;
    }
    return wl_vch_push(script,bytes,len);
}

int wl_sato_script_parse_op(vch_t *script,struct sato_script_op *op,size_t *count)
{
    uint8_t *s = wl_vch_data(script);
    size_t len = wl_vch_len(script);
    size_t pc = 0,n = 0;
    uint8_t opcode;
    memset(op,0,sizeof(struct sato_script_op) * (*count));
    if (s == NULL && len == 0)
    {
        return -1;
    }
    while (pc < len && n < (*count))
    {
        opcode = s[pc++];
        op[n].opcode = opcode;
        if (opcode < OP_PUSHDATA1)
        {
            op[n].size = opcode;
            op[n].data = &s[pc];
            pc += op[n].size;
        }
        else if (opcode >= OP_PUSHDATA1 && opcode <= OP_PUSHDATA4)
        {
            int l = opcode - OP_PUSHDATA1 + 1;
            if (pc + l > len)
            {
                return -1;
            }
            memcpy(&op[n].size,&s[pc],l);
            pc += l;
            op[n].data = &s[pc];
            pc += op[n].size;
        }
        n++;
    }
    if (pc != len || n == 0)
    {
        return -1;
    }

    *count = n;
    return 0;
}

int wl_sato_script_match_template(struct sato_script_op *op,size_t count,
                                  const uint8_t *opt,size_t len)
{
    const uint8_t *pc = opt;
    size_t i = 0;
    while (pc - opt < len && i < count)
    {
        if (*pc < OP_SMALLDATA)
        {
            if (*pc != op[i++].opcode)
            {
                break;
            }
        }
        else if (*pc == OP_SMALLDATA)
        {
            if (op[i].data == NULL || op[i].size > 80)
            {
                break;
            }
            i++;
        }
        else if (*pc == OP_SMALLINTEGER)
        {
            if (op[i].opcode != OP_0 && (op[i].opcode < OP_1 || op[i].opcode > OP_16))
            {
                break;
            }
            i++;
        }
        else if (*pc == OP_PUBKEY || *pc == OP_PUBKEYS) 
        {
            if (op[i].data == NULL || op[i].size < 33 || op[i].size > 120)
            {
                break;
            }
            i++;
            if (*pc == OP_PUBKEYS)
            {
                while (i < count && op[i].data != NULL 
                       && op[i].size >= 33 && op[i].size <= 120)
                {
                    i++;
                }
            }
        }
        else if (*pc == OP_PUBKEYHASH)
        {
            if (op[i].data == NULL || op[i].size != 20)
            {
                break;
            }
            i++;
        }
        ++pc;
    }
    return (pc - opt == len && i == count ? 0 : -1);
}

int wl_sato_script_extract_dest(vch_t *script_pk,struct sato_script_dest *dest)
{
    const uint8_t p2pk[] = {OP_PUBKEY,OP_CHECKSIG};
    const uint8_t p2ph[] = {OP_DUP,OP_HASH160,OP_PUBKEYHASH,OP_EQUALVERIFY,OP_CHECKSIG};
    const uint8_t p2sh[] = {OP_HASH160,OP_PUBKEYHASH,OP_EQUAL};

    struct sato_script_op op[5];
    size_t count = 5;
    if (wl_sato_script_parse_op(script_pk,op,&count) < 0)
    {
        return -1;
    }
    dest->outtype = TX_NONSTANDARD;
 
    if (count == 2)
    {
        if (wl_sato_script_match_template(op,count,p2pk,sizeof(p2pk)) == 0)
        {
            dest->outtype = TX_PUBKEY; 
            wl_hash160(op[0].data,op[0].size,&dest->id);
        }
    }
    else if (count == 5)
    {
        if (wl_sato_script_match_template(op,count,p2ph,sizeof(p2ph)) == 0)
        {
            dest->outtype = TX_PUBKEYHASH; 
            memcpy(&dest->id,op[2].data,20);
        }
    }
    else if (count == 3)
    {
        if (wl_sato_script_match_template(op,count,p2sh,sizeof(p2sh)) == 0)
        {
            dest->outtype = TX_SCRIPTHASH; 
            memcpy(&dest->id,op[1].data,20);
        }
    }
    return (dest->outtype != TX_NONSTANDARD ? 0 : -1);
}

int wl_sato_script_extract_redeem(vch_t *script_sig,vch_t *redeem)
{
    struct sato_script_op op[18];
    size_t n = 18;
    if (wl_sato_script_parse_op(script_sig,op,&n) == 0
        && n > 0 && op[n - 1].data != NULL)
    {
        wl_vch_clear(redeem);
        return wl_vch_push(redeem,op[n - 1].data,op[n - 1].size);
    }
    return -1; 
}

int wl_sato_script_solver_multisig(struct sato_script_op *op,size_t count,
                                   struct sato_multisig_ctxt *multisig)
{
    const uint8_t opt[] = {OP_SMALLINTEGER,OP_PUBKEYS,OP_SMALLINTEGER,OP_CHECKMULTISIG};

    if (wl_sato_script_match_template(op,count,opt,sizeof(opt)) == 0
        && count == op[count - 2].opcode - OP_1 + 1 + 3 && count - 3 <= 3)
    {
        int i;
        multisig->req = op[0].opcode - OP_1 + 1;
        multisig->count = count - 3;

        for (i = 1;i < count - 2;i++)
        {
            memcpy(multisig->pubkeys[i - 1],op[i].data,op[i].size);
            multisig->size[i - 1] = op[i].size;
        }
        return 0;
    }
    return -1;
}

int wl_sato_script_build_multisig(struct sato_multisig_ctxt *multisig,vch_t *script)
{
    int i;
    if (multisig == NULL || script == NULL || multisig->count > 3)
    {
        return -1;
    }

    wl_vch_clear(script);

    if (wl_sato_script_push_number(script,multisig->req) < 0)
    {
        return -1;
    }
    for (i = 0;i < multisig->count;i++)
    {
        if (wl_sato_script_push_bytes(script,multisig->pubkeys[i],multisig->size[i]) < 0)
        {
            return -1;
        }
    }
    if (wl_sato_script_push_number(script,multisig->count) < 0)
    {
        return -1;
    }
    return wl_sato_script_push_opcode(script,OP_CHECKMULTISIG);
}

int wl_sato_script_validate_pubkey(uint256_t *hash,vch_t *script_pk,vch_t *script_sig)
{
    struct sato_script_op op[1];
    size_t n = 1;
    if (script_pk != NULL && script_sig != NULL 
        && wl_sato_script_parse_op(script_sig,op,&n) == 0 && n == 1
        && op[0].data != NULL && op[0].size > 1)
    {
        uint8_t *p = wl_vch_data(script_pk);
        int compress = *p == 33 ? 1 : 0;
        return wl_secp_verify_signature(&p[1],compress,hash,op[0].data,op[0].size - 1);
    }
    return -1;
}

int wl_sato_script_validate_pubkeyhash(uint256_t *hash,vch_t *script_pk,vch_t *script_sig)
{
    struct sato_script_op op[2];
    size_t n = 2;
    
    if (script_pk != NULL && script_sig != NULL 
        && wl_sato_script_parse_op(script_sig,op,&n) == 0 && n == 2
        && op[0].data != NULL && op[0].size > 1 
        && op[1].data != NULL && (op[1].size == 33 || op[1].size == 65))
    {
        uint8_t *p = wl_vch_data(script_pk);
        int compress = op[1].size == 33 ? 1 : 0;
        uint160_t keyhash = UINT160_ZERO;
        wl_hash160(op[1].data,op[1].size,&keyhash);
        if (memcmp(keyhash.u8,&p[3],20) == 0)
        {
            return wl_secp_verify_signature(op[1].data,compress,hash,op[0].data,op[0].size - 1);
        }
    }
    return -1;
}

int wl_sato_script_validate_scripthash(vch_t *script_pk,vch_t *script_sig,vch_t *redeem)
{
    struct sato_script_op op[18];
    size_t n = 18;
    if (wl_sato_script_parse_op(script_sig,op,&n) == 0
        && n > 0 && op[n - 1].data != NULL)
    {
        uint8_t *p = wl_vch_data(script_pk);
        uint160_t hash = UINT160_ZERO;
        wl_hash160(op[n - 1].data,op[n - 1].size,&hash);
        if (memcmp(hash.u8,&p[2],20) == 0)
        {
            wl_vch_clear(redeem);
            return wl_vch_push(redeem,op[n - 1].data,op[n - 1].size);
        }
    }
    return -1; 
}

int wl_sato_script_validate_multisig(struct sato_multisig_ctxt *multisig,uint256_t *hash,
                                     vch_t *redeem,vch_t *script_sig,vch_t *sig[])
{
    struct sato_script_op op[5];
    size_t n = 5,i,j,s = 0;
    if (multisig == NULL || redeem == NULL || script_sig == NULL || sig == NULL
        || wl_sato_script_parse_op(script_sig,op,&n) < 0 
        || op[0].opcode != OP_0 
        || op[n - 1].data == NULL || wl_vch_cmp_data(redeem,op[n - 1].data,op[n - 1].size) != 0)
    {
        return -1;
    }
    for (j = 0; j < multisig->count; j++)
    {
        if (sig[j] == NULL)
        {
            return -1;
        }
        wl_vch_clear(sig[j]);
    }
    for (i = 0; i < multisig->req && op[i + 1].opcode != OP_0; i++)
    {
        if (op[i + 1].data == NULL)
        {
            return -1;
        }
        for (j = 0; j < multisig->count; j++)
        {
            if (wl_vch_len(sig[j]) == 0)
            {
                int compress = multisig->size[j] == 33 ? 1 : 0;
                if (wl_secp_verify_signature(multisig->pubkeys[j],compress,hash,
                                             op[i + 1].data,op[i + 1].size - 1) == 0)
                {
                    if (wl_vch_push(sig[j],op[i + 1].data,op[i + 1].size) < 0)
                    {
                        return -1;
                    }
                    s++;
                    break;
                }
            }
        }
    }
    return s; 
}

int wl_sato_script_combine_multisig(struct sato_multisig_ctxt *multisig,vch_t *sig[],vch_t *script_sig)
{
    size_t i,j = 0;
    if (multisig == NULL || script_sig == NULL || sig == NULL)
    {
        return -1;
    }
    wl_vch_clear(script_sig);
    
    if (wl_sato_script_push_opcode(script_sig,OP_0) < 0)
    {
        return -1;
    }

    for (i = 0; i < multisig->req; i++)
    {       
        while (j < multisig->count && wl_vch_len(sig[j]) == 0)
        {
            j++;
        }
        if (j < multisig->count)
        {
            if (wl_sato_script_push_data(script_sig,sig[j++]) < 0)
            {
                return -1;
            }
        } 
        else if (wl_sato_script_push_opcode(script_sig,OP_0) < 0)
        {
            return -1;
        }
    }
    return 0;
}
