// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdarg.h>
#include <stdio.h>

#include "vch.h"
#include "hex.h"

#define MIN_VCH_SIZE		64

static inline vch_t *wl_vch_alloc(size_t size)
{
    vch_t *vch = ((vch_t *)calloc(1,sizeof(vch_t)));
    vch->size = size > MIN_VCH_SIZE ? size : MIN_VCH_SIZE;
    if ((vch->ptr = (uint8_t*)calloc(1,vch->size)) == NULL)
    {
        free(vch);
        vch = NULL;
    }
    return vch;
}

static inline uint8_t *wl_vch_realloc(vch_t *vch,size_t size)
{
    if (vch->size < size)
    {
        vch->size = (((size + 64) >> 6) << 7);
        if ((vch->ptr = (uint8_t *)realloc(vch->ptr,vch->size)) != NULL)
        {
            memset(vch->ptr + vch->len,0,vch->size - vch->len);
        }
    }
    return vch->ptr;
}

vch_t *wl_vch_new(void)
{
    return wl_vch_alloc(MIN_VCH_SIZE);
}

vch_t *wl_vch_new_str(const char *str)
{
    size_t len = strlen(str);
    vch_t *vch = wl_vch_alloc(len + 1);
    if (vch != NULL)
    {
        if (wl_vch_push(vch,(const uint8_t *)str,len) < 0)
        {
            wl_vch_free(vch);
            vch = NULL;
        } 
    }
    return vch;
}

vch_t *wl_vch_new_hex(const char *hex)
{
    size_t len = strlen(hex) / 2;
    vch_t *vch = wl_vch_alloc(len + 1);;
    if (vch != NULL)
    {
        int h,l;
        while (*hex != '\0')
        {
            if ((h = wl_hex_to_int(*hex++)) < 0 
                || (l = wl_hex_to_int(*hex++)) < 0
                || wl_vch_push_uchar(vch,(h << 4) | l) < 0)
            {
                wl_vch_free(vch);
                vch = NULL;
                break; 
            }
        }
    }
    return vch;
}

vch_t *wl_vch_clone(const vch_t *src)
{
    vch_t *vch = wl_vch_new();
    if (vch != NULL)
    {
        if (wl_vch_push(vch,src->ptr,src->len) < 0)
        {
            wl_vch_free(vch);
            vch = NULL;
        }
    }
    return vch;
}

void wl_vch_free(vch_t *vch)
{
    if (vch != NULL)
    {
        if (vch->ptr != NULL)
        {
            free(vch->ptr);
        }
        free(vch);
    }
}

void wl_vch_clear(vch_t *vch)
{
    if (vch->ptr != NULL)
    {
        memset(vch->ptr,0,vch->len);
    }
    vch->len = 0;
}

void wl_vch_reserve(vch_t *vch,size_t size)
{
    wl_vch_realloc(vch,size);
}

int wl_vch_resize(vch_t *vch,size_t size)
{
    if (size < vch->len)
    {
        memset(vch->ptr + size,0,vch->len - size);
    }
    else if (size > vch->len)
    {
        if (wl_vch_realloc(vch,size) == NULL)
        {
            return -1;
        }
    }
    vch->len = size;
    return 0;
}

int wl_vch_push(vch_t *vch,const uint8_t *bytes,size_t size)
{
    size_t len = vch->len + size;

    if (vch->size < len + 1)
    {
        if (wl_vch_realloc(vch,len + 1) == NULL)
        {
            return -1;
        }
    }
    memcpy(vch->ptr + vch->len,bytes,size);
    vch->len = len;
    return 0;
}

int wl_vch_push_uchar(vch_t *vch,const uint8_t u)
{
    if (vch->size < vch->len + 1)
    {
        if (wl_vch_realloc(vch,vch->len + 1) == NULL)
        {
            return -1;
        }
    }

    vch->ptr[vch->len++] = u;
    return 0;
}

int wl_vch_push_sprintf(vch_t *vch,const char *fmt,...)
{
    int len = 0;
    va_list ap;
    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (len < 0)
    {
        return -1;
    }
    
    if (vch->size < vch->len + len + 1)
    {
        if (wl_vch_realloc(vch,vch->len + len + 1) == NULL)
        {
            return -1;
        }
    }
    va_start(ap, fmt);
    vsnprintf((char *)vch->ptr + vch->len, len + 1, fmt, ap);
    va_end(ap);
    vch->len += len;
    return 0;
}

int wl_vch_push_hex(vch_t *vch,const uint8_t *bytes,size_t size)
{
    int i;
    char *p;
    if (vch->size < vch->len + size * 2 + 1)
    {
        if (wl_vch_realloc(vch,vch->len + size * 2 + 1) == NULL)
        {
            return -1;
        }
    }
    
    p = (char *)vch->ptr + vch->len; 
    for (i = 0;i < size;i++)
    {
        *p++ = wl_hex_to_char(bytes[i] >> 4);
        *p++ = wl_hex_to_char(bytes[i] & 15);
    }
    vch->len += size * 2; 
    return 0;
}

int wl_vch_push_rhex(vch_t *vch,const uint8_t *bytes,size_t size)
{
    int i;
    char *p;
    if (vch->size < vch->len + size * 2 + 1)
    {
        if (wl_vch_realloc(vch,vch->len + size * 2 + 1) == NULL)
        {
            return -1;
        }
    }
    
    p = (char *)vch->ptr + vch->len; 
    for (i = size;i > 0;i--)
    {
        *p++ = wl_hex_to_char(bytes[i - 1] >> 4);
        *p++ = wl_hex_to_char(bytes[i - 1] & 15);
    }
    vch->len += size * 2; 
    return 0;
}
