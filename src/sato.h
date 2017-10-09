// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_SATO_H
#define  WALLEVE_SATO_H

#include <stdlib.h>
#include <stdint.h>
#include "coins.h"
#include "vch.h"

#define SIGHASH_ALL             1

enum opcodetype
{
    OP_0                  = 0x00,
    OP_PUSHDATA1          = 0x4c,
    OP_PUSHDATA2          = 0x4d,
    OP_PUSHDATA4          = 0x4e,
    OP_1                  = 0x51,
    OP_16                 = 0x60,
    OP_IF                 = 0x63,
    OP_ELSE               = 0x67,
    OP_ENDIF              = 0x68,
    OP_DUP                = 0x76,
    OP_EQUAL              = 0x87,
    OP_EQUALVERIFY        = 0x88,
    OP_HASH160            = 0xa9,
    OP_CHECKSIG           = 0xac,
    OP_CHECKMULTISIG      = 0xae,
    // template matching params
    OP_SMALLDATA          = 0xf9,
    OP_SMALLINTEGER       = 0xfa,
    OP_PUBKEYS            = 0xfb,
    OP_PUBKEYHASH         = 0xfd,
    OP_PUBKEY             = 0xfe,
};

enum txnouttype
{
    TX_NONSTANDARD = 0,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
};

struct sato_script_op
{
    uint8_t opcode;
    uint8_t *data;
    size_t   size;
};

struct sato_script_dest
{
    uint8_t outtype;
    uint160_t id;
};

struct sato_multisig_ctxt
{
    uint8_t req;
    uint8_t count;
    uint8_t pubkeys[3][65];
    uint8_t size[3];
};

/* Address */

int wl_sato_md20_address(uint8_t prefix,void *md20,char *addr,size_t len);
int wl_sato_pubkey_address(uint8_t prefix,const uint8_t *pubkey,size_t size,char *addr,size_t len);
int wl_sato_script_address(uint8_t prefix,vch_t *script,char *addr,size_t len);

/* Script */

int wl_sato_script_push_opcode(vch_t *script,uint8_t opcode);
int wl_sato_script_push_number(vch_t *script,uint8_t number);
int wl_sato_script_push_data(vch_t *script,vch_t* vch);
int wl_sato_script_push_bytes(vch_t *script,uint8_t *bytes,size_t len);

int wl_sato_script_parse_op(vch_t *script,struct sato_script_op *op,size_t *count);
int wl_sato_script_match_template(struct sato_script_op *op,size_t count,
                                  const uint8_t *opt,size_t len);
int wl_sato_script_extract_dest(vch_t *script_pk,struct sato_script_dest *dest);
int wl_sato_script_extract_redeem(vch_t *script_sig,vch_t *redeem);
int wl_sato_script_solver_multisig(struct sato_script_op *op,size_t count,
                                   struct sato_multisig_ctxt *multisig);
int wl_sato_script_build_multisig(struct sato_multisig_ctxt *multisig,vch_t *script);

int wl_sato_script_validate_pubkey(uint256_t *hash,vch_t *script_pk,vch_t *script_sig);
int wl_sato_script_validate_pubkeyhash(uint256_t *hash,vch_t *script_pk,vch_t *script_sig);
int wl_sato_script_validate_scripthash(vch_t *script_pk,vch_t *script_sig,vch_t *redeem);
int wl_sato_script_validate_multisig(struct sato_multisig_ctxt *multisig,uint256_t *hash,
                                     vch_t *redeem,vch_t *script_sig,vch_t *sig[]);
int wl_sato_script_combine_multisig(struct sato_multisig_ctxt *multisig,vch_t *sig[],vch_t *script_sig);
                                   
#endif //WALLEVE_SATO_H

