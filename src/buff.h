// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
    
#ifndef  WALLEVE_BUFF_H
#define  WALLEVE_BUFF_H

#include <stdlib.h>
#include <stdint.h>
#include "vch.h"

typedef struct
{
    vch_t *vch;
    size_t start;      //read offset
}buff_t;

int wl_buff_init(buff_t *buf);
int wl_buff_init_hex(buff_t *buf,const char *hex);

void wl_buff_deinit(buff_t *buf);
void wl_buff_clear(buff_t *buf);

int wl_buff_push_bytes(buff_t *buf,const uint8_t *bytes,size_t size);
int wl_buff_push_varint(buff_t *buf,size_t s);

int wl_buff_pop_bytes(buff_t *buf,uint8_t *bytes,size_t size);
int wl_buff_pop_varint(buff_t *buf,size_t *s);

inline int wl_buff_push8(buff_t *buf,uint8_t u)
{
    return wl_buff_push_bytes(buf,&u,sizeof(uint8_t));
}

inline int wl_buff_push16(buff_t *buf,uint16_t u)
{
    return wl_buff_push_bytes(buf,(uint8_t *)&u,sizeof(uint16_t));
}

inline int wl_buff_push32(buff_t *buf,uint32_t u)
{
    return wl_buff_push_bytes(buf,(uint8_t *)&u,sizeof(uint32_t));
}

inline int wl_buff_push64(buff_t *buf,uint64_t u)
{
    return wl_buff_push_bytes(buf,(uint8_t *)&u,sizeof(uint64_t));
}

inline int wl_buff_pop8(buff_t *buf,uint8_t *u)
{
    return wl_buff_pop_bytes(buf,u,sizeof(uint8_t));
}

inline int wl_buff_pop16(buff_t *buf,uint16_t *u)
{
    return wl_buff_pop_bytes(buf,(uint8_t *)u,sizeof(uint16_t));
}

inline int wl_buff_pop32(buff_t *buf,uint32_t *u)
{
    return wl_buff_pop_bytes(buf,(uint8_t *)u,sizeof(uint32_t));
}

inline int wl_buff_pop64(buff_t *buf,uint64_t *u)
{
    return wl_buff_pop_bytes(buf,(uint8_t *)u,sizeof(uint64_t));
}

#endif //WALLEVE_BUFF_H

