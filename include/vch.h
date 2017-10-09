// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_VCH_H
#define  WALLEVE_VCH_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
    /* data length */
    size_t len;
    /* buffer capacity */
    size_t size;
    /* buffer address */
    uint8_t *ptr;
}vch_t;

// Alloc vch object
vch_t *wl_vch_new(void);

// Create vch object & initialize as specified string
vch_t *wl_vch_new_str(const char *str);

// Create vch object & initialize as binary (from hex string)
vch_t *wl_vch_new_hex(const char *hex);

// Create vch object & clone from src
vch_t *wl_vch_clone(const vch_t *src);

// Release vch object
void wl_vch_free(vch_t *vch);

// Clear object buffer
void wl_vch_clear(vch_t *vch);

// Change buffer capacity
void wl_vch_reserve(vch_t *vch,size_t size);

// Resize data
int wl_vch_resize(vch_t *vch,size_t size);

// Append data
int wl_vch_push(vch_t *vch,const uint8_t *bytes,size_t size);

// Append unsigned char
int wl_vch_push_uchar(vch_t *vch,const uint8_t u);

// Append format string
int wl_vch_push_sprintf(vch_t *vch,const char *fmt,...);

// Append hex string from specified data
int wl_vch_push_hex(vch_t *vch,const uint8_t *bytes,size_t size);

// Append hex string from specified data (revesed order)
int wl_vch_push_rhex(vch_t *vch,const uint8_t *bytes,size_t size);

// Return data length
inline size_t wl_vch_len(vch_t *vch)
{
    return vch->len;
}

// Return data address
inline void *wl_vch_data(vch_t *vch)
{
    return (vch ? vch->ptr : NULL);
}

// Return c string
inline char *wl_vch_string(vch_t *vch)
{
    return ((char *)(vch ? vch->ptr : NULL));
}

// Copy data from other vch object
inline int wl_vch_copy(vch_t *vch,const vch_t *src)
{
    wl_vch_clear(vch);
    return wl_vch_push(vch,src->ptr,src->len);
}

// Concatenate other vch object
inline int wl_vch_cat(vch_t *vch,const vch_t *src)
{
    return wl_vch_push(vch,src->ptr,src->len);
}

// Append string
inline int wl_vch_push_string(vch_t *vch,const char *str)
{
    return wl_vch_push(vch,(const uint8_t *)str,strlen(str));
}

// Compare with data
inline int wl_vch_cmp_data(vch_t *vch,const void *data,size_t len)
{
    return (vch->len == len ? memcmp(vch->ptr,data,len) : vch->len - len);
}

// Compare with other vch object
inline int wl_vch_cmp(vch_t *vch,const vch_t *other)
{
    return wl_vch_cmp_data(vch,other->ptr,other->len);
}

// Compare with string
inline int wl_vch_cmp_string(vch_t *vch,const char *str)
{
    return strcmp(wl_vch_string(vch),str);
}


#endif //WALLEVE_VCH_H
