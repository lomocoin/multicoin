// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_RLP_H
#define  WALLEVE_RLP_H
#include <stdlib.h>
#include <stdint.h>

#include "vch.h"

enum
{
    RLP_NULL = 0,
    RLP_BYTE = 1,
    RLP_STR  = 2,
    RLP_LIST = 3,
};

typedef struct
{
    uint8_t type;
    union
    {
        uint8_t val;
        const uint8_t *ptr;
    } ref;
    size_t len;
}rlp_t;


int wl_rlp_put_uint(vch_t *rlp,uint64_t u);
int wl_rlp_put_data(vch_t *rlp,const uint8_t *data,size_t len);
int wl_rlp_put_biguint(vch_t *rlp,const uint8_t *u,size_t len);
int wl_rlp_put_list(vch_t *rlp,vch_t *list);

int wl_rlp_tohex(vch_t *rlp,vch_t *hex);

int wl_rlp_parse_list(const uint8_t *data,size_t len,rlp_t *rlp,int max_count);

int wl_rlp_get_uint(rlp_t *rlp,uint64_t *u);
int wl_rlp_get_data(rlp_t *rlp,vch_t *vch);
int wl_rlp_get_biguint(rlp_t *rlp,uint8_t *u,size_t len);
int wl_rlp_get_list(rlp_t *rlp,vch_t *list);

#endif //WALLEVE_RLP_H
