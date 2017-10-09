// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "string.h"
#include "buff.h"
#include "hex.h"

#define VAR_INT16_HEADER  0xfd
#define VAR_INT32_HEADER  0xfe
#define VAR_INT64_HEADER  0xff

int wl_buff_init(buff_t *buf)
{
    buf->start = 0;
    if ((buf->vch = wl_vch_new()) != NULL)
    {
        wl_vch_reserve(buf->vch,1024);
        return 0;
    }
    return -1; 
}

int wl_buff_init_hex(buff_t *buf,const char *hex)
{
    buf->start = 0;
    if ((buf->vch = wl_vch_new_hex(hex)) != NULL)
    {
        return 0;
    }
    return -1; 
}

void wl_buff_deinit(buff_t *buf)
{
    wl_vch_free(buf->vch);
    buf->vch = NULL;
    buf->start = 0;
}

void wl_buff_clear(buff_t *buf)
{
    wl_vch_clear(buf->vch);
    buf->start = 0;
}

int wl_buff_push_bytes(buff_t *buf,const uint8_t *bytes,size_t size)
{
    return wl_vch_push(buf->vch,bytes,size);
}

int wl_buff_push_varint(buff_t *buf,size_t s)
{
    if (s < VAR_INT16_HEADER)
    {
        return wl_buff_push8(buf,s);
    }
    else if (s <= 0xFFFF)
    {
        if (wl_buff_push8(buf,VAR_INT16_HEADER) < 0)
        {
            return -1;
        }
        return wl_buff_push16(buf,s);
    }
    else if (s <= 0xFFFFFFFF)
    {
        if (wl_buff_push8(buf,VAR_INT32_HEADER) < 0)
        {
            return -1;
        }
        return wl_buff_push32(buf,s);
    }
    return -1;
}

int wl_buff_pop_bytes(buff_t *buf,uint8_t *bytes,size_t size)
{
    if (wl_vch_len(buf->vch) - buf->start < size)
    {
        return -1;
    }
    memcpy(bytes,((uint8_t*)wl_vch_data(buf->vch)) + buf->start,size);
    buf->start += size;
    return 0;
}

int wl_buff_pop_varint(buff_t *buf,size_t *s)
{
    uint8_t u;
    if (wl_buff_pop8(buf,&u) < 0)
    {
        return -1;
    }
    *s = 0;
    switch (u)
    {
    case VAR_INT16_HEADER:
        return wl_buff_pop_bytes(buf,(uint8_t *)s,sizeof(uint16_t));
    case VAR_INT32_HEADER:
        return wl_buff_pop_bytes(buf,(uint8_t *)s,sizeof(uint32_t));
    case VAR_INT64_HEADER:
        return -1;
    default:
        *s = u;
        break;
    }
    return 0;
}

