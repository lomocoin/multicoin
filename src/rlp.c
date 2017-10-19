// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rlp.h"

static inline size_t wl_rlp_uint_length(uint64_t u)
{
    size_t l = 0;
    while (u)
    {   
        u >>= 8;++l;
    }
    return l;
}

static inline size_t wl_rlp_biguint_length(const uint8_t *u,size_t len)
{
    size_t l = 0;
    while (l < len && !(*u++))
    {   
        l++;
    }
    return (len - l);
}

static inline int wl_rlp_write_uint_be(vch_t *rlp,uint64_t i,size_t l)
{
    while (l--)
    {
        if (wl_vch_push_uchar(rlp,(i >> (l << 3)) & 0xff) < 0)
        {   
            return -1;
        }
    }
    return 0;
}

static inline int wl_rlp_put(vch_t *rlp,const uint8_t *data,size_t len,const uint8_t start)
{
    uint8_t lstart = start + 0x37;
    if (len < 56)
    {
        if (wl_vch_push_uchar(rlp,start + len) < 0)
        {
            return -1;
        }
    }
    else
    {
        size_t l = wl_rlp_uint_length(len);
        if (wl_vch_push_uchar(rlp,lstart + l) < 0
            || wl_rlp_write_uint_be(rlp,len,l) < 0)
        {
            return -1;
        }
    }
    return wl_vch_push(rlp,data,len);
}


int wl_rlp_put_uint(vch_t *rlp,uint64_t u)
{
    size_t l;
    if (u == 0)
    {
        return wl_vch_push_uchar(rlp,0x80);
    }
    else if (u < 0x80)
    {
        return wl_vch_push_uchar(rlp,u);
    }

    l = wl_rlp_uint_length(u);
    if (wl_vch_push_uchar(rlp,0x80 + l) < 0)
    {
        return -1;
    }
    return wl_rlp_write_uint_be(rlp,u,l);
}

int wl_rlp_put_data(vch_t *rlp,const uint8_t *data,size_t len)
{
    if (len == 1 && *data < 0x80)
    {
        return wl_vch_push_uchar(rlp,*data);
    }
    return wl_rlp_put(rlp,data,len,0x80);
}

int wl_rlp_put_biguint(vch_t *rlp,const uint8_t *u,size_t len)
{
    size_t l = wl_rlp_biguint_length(u,len);
    if (l == 0)
    {
        return wl_vch_push_uchar(rlp,0x80);
    }
    return wl_rlp_put_data(rlp,u + len - l,l);
}


int wl_rlp_put_list(vch_t *rlp,vch_t *list)
{
    return wl_rlp_put(rlp,wl_vch_data(list),wl_vch_len(list),0xc0);
}

int wl_rlp_tohex(vch_t *rlp,vch_t *hex)
{
    uint8_t hdr[9];
    size_t count = 0;
    size_t len = wl_vch_len(rlp);

    if (len < 56)
    {
        hdr[count++] = 0xc0 + len;
    }
    else
    {
        size_t l = wl_rlp_uint_length(len);
        hdr[count++] = 0xf7 + l;
        while (l--)
        {
            hdr[count++] = (len >> (l << 3)) & 0xff;
        }
    }
    wl_vch_clear(hex);
    if (wl_vch_push_hex(hex,hdr,count) < 0
        || wl_vch_push_hex(hex,wl_vch_data(rlp),len) < 0)
    {
        return -1;
    }
    return 0; 
}

static inline uint64_t wl_rlp_read_uint_be(const uint8_t *p,size_t l)
{
    uint64_t u = 0;
    while (l--)
    {
        u = (u << 8) + (*p++);
    }
    return u;
}

static inline void wl_rlp_read_biguint_be(const uint8_t *p,size_t l,uint8_t *u,size_t len)
{
    while (len-- > l)
    {
        *u++ = 0;
    }
    while (l--)
    {
        *u++ = *p++;
    }
}

static inline int wl_rlp_get(const uint8_t *start,const uint8_t *end,
                             rlp_t *rlp,const uint8_t **endp)
{
    uint8_t t = *start++;
    if (t <= 0x80)
    {
        rlp->type = RLP_BYTE;
        rlp->ref.val = (t == 0x80 ? 0 : t);
        rlp->len = 1;
        *endp = start;
    }
    else 
    {
        if (t < 0xc0)
        {
            rlp->type = RLP_STR;
            t -= 0x80;
        }
        else
        {
            rlp->type = RLP_LIST;
            t -= 0xc0;
        }

        if (t <= 0x37)
        {
            rlp->len = t;
        }
        else 
        {
            uint8_t l = t - 0x37;
            if (start + l > end)
            {
                return -1;
            }
            rlp->len = wl_rlp_read_uint_be(start,l);
            start += l;
        }
        rlp->ref.ptr = start;
        *endp = start + rlp->len;
    }
    return  (*endp > end ? -1 : 0);
}

int wl_rlp_parse_list(const uint8_t *data,size_t len,rlp_t *rlp,int max_count)
{
    const uint8_t *end = data + len;
    const uint8_t *ep;
    int count = 0;
    rlp_t self;
    
    if (wl_rlp_get(data,end,&self,&ep) < 0
        || self.type != RLP_LIST || end != ep)
    {
        return -1;
    }

    data = self.ref.ptr;
    while (data < end && count < max_count)
    {
        if (wl_rlp_get(data,end,&rlp[count++],&ep) < 0)
        {
            return -1;
        }
        data = ep;
    }
    return count;
}

int wl_rlp_get_uint(rlp_t *rlp,uint64_t *u)
{
    if (rlp->type == RLP_BYTE)
    {
        *u = rlp->ref.val;
        return 0;
    }
    else if (rlp->type == RLP_STR && rlp->len < 8)
    {
        *u = wl_rlp_read_uint_be(rlp->ref.ptr,rlp->len);
        return 0;
    }
    return -1;
}

int wl_rlp_get_data(rlp_t *rlp,vch_t *vch)
{
    wl_vch_clear(vch);
    if (rlp->type == RLP_BYTE)
    {
        if (rlp->ref.val == 0)
        {
            return 0;
        }
        return wl_vch_push_uchar(vch,rlp->ref.val);
    }
    else if (rlp->type == RLP_STR)
    {
        return wl_vch_push(vch,rlp->ref.ptr,rlp->len);
    }
    return -1;
}

int wl_rlp_get_biguint(rlp_t *rlp,uint8_t *u,size_t len)
{
    if (rlp->type == RLP_BYTE)
    {
        memset(u,0,len - 1);
        u[len - 1] = rlp->ref.val;
        return 0;
    }
    else if (rlp->type == RLP_STR)
    {
        wl_rlp_read_biguint_be(rlp->ref.ptr,rlp->len,u,len);
        return 0;
    } 
    return -1;
}

int wl_rlp_get_list(rlp_t *rlp,vch_t *list)
{
    wl_vch_clear(list);
    if (rlp->type == RLP_LIST)
    {
        return wl_vch_push(list,rlp->ref.ptr,rlp->len);
    }
    return -1;
}
