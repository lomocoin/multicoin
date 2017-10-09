// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdlib.h>
#include <string.h>
#include "key.h"
#include "crypto.h"

struct wl_key_list
{
    struct wl_key_list *next;
    char addr[47];
    uint8_t secret[32];
    uint8_t pubkey[65];
};

static struct wl_key_list *_key_list[WALLEVE_COINS_COUNT] = {NULL,};

static inline void wl_key_insert_list(coin_t coin,struct wl_key_list *p)
{
    p->next = _key_list[coin];
    _key_list[coin] = p;
}

static inline void wl_key_remove_list(coin_t coin,const char *addr)
{
    struct wl_key_list *p = _key_list[coin];
    struct wl_key_list *q = NULL;
    while(p != NULL)
    {
        if (strcmp(addr,p->addr) == 0)
        {
            if (q != NULL)
            {
                q->next = p->next;
            }
            else
            {
                _key_list[coin] = p->next;
            }
            free(p);
            break;
        }
        q = p;p = p->next;
    }
}

static inline struct wl_key_list *wl_key_find_list(coin_t coin,const char *addr)
{
    struct wl_key_list *p = _key_list[coin];
    while(p != NULL)
    {
        if (strcmp(addr,p->addr) == 0)
        {
            break;
        }
        p = p->next;
    }
    return p;
}

void wl_key_init()
{
}

void wl_key_clear()
{
    int i;
    struct wl_key_list *q,*p;

    for (i = 0;i < WALLEVE_COINS_COUNT;i++)
    {
        p = _key_list[i];
        while(p != NULL)
        {
            q = p;p = p->next;
            free(q);
        }
        _key_list[i] = NULL;
    }
}

static int wl_key_update(coin_t coin,struct wl_key_list *p,vch_t *addr)
{
    struct wl_coin_operation *op = wl_get_coin_operation(coin);
    vch_t *pk = wl_vch_new();
    if (pk == NULL || wl_secp_get_pubkey(p->secret,op->is_compressed(),pk) < 0)
    {
        wl_vch_free(pk);
        return -1;
    }
    
    memcpy(p->pubkey,wl_vch_data(pk),wl_vch_len(pk));
    wl_vch_free(pk);

    if (op->get_addr(p->pubkey,p->addr,46) < 0)
    {
        return -1;
    }

    wl_vch_clear(addr);
    if (wl_vch_push_string(addr,p->addr) < 0)
    {
        return -1;
    }

    return 0;
}

int wl_key_create(coin_t coin,vch_t *addr)
{
    struct wl_key_list *p = (struct wl_key_list *)calloc(1,sizeof(struct wl_key_list));

    if (p != NULL)
    {
        do
        {
            wl_rand_data(p->secret,32);
        } while (wl_secp_verify_secret(p->secret) < 0);

        if (wl_key_update(coin,p,addr) == 0)
        {
            wl_key_remove_list(coin,p->addr);
            wl_key_insert_list(coin,p);
            return 0;
        }
        free(p);
    }
    return -1;
}

int wl_key_import(coin_t coin,const char *privkey,vch_t *addr)
{
    struct wl_key_list *p = (struct wl_key_list *)calloc(1,sizeof(struct wl_key_list));
    if (p != NULL)
    {
        struct wl_coin_operation *op = wl_get_coin_operation(coin);
        if (op->set_priv(privkey,p->secret) == 0 
            && wl_secp_verify_secret(p->secret) == 0
            && wl_key_update(coin,p,addr) == 0)
        {
            wl_key_remove_list(coin,p->addr);
            wl_key_insert_list(coin,p);
            return 0;
        }
        free(p);
    }
    return -1;
}

void wl_key_remvoe(coin_t coin,const char *addr)
{
    wl_key_remove_list(coin,addr);
}

int wl_key_privkey(coin_t coin,const char *addr,vch_t *privkey)
{
    struct wl_key_list *p = wl_key_find_list(coin,addr);
    if (p != NULL)
    {
        return wl_get_coin_operation(coin)->get_priv(p->secret,privkey);
    }
    return -1;
}

int wl_key_pubkey(coin_t coin,const char *addr,vch_t *pubkey)
{
    struct wl_key_list *p = wl_key_find_list(coin,addr);
    if (p != NULL)
    {
        struct wl_coin_operation *op = wl_get_coin_operation(coin);
        size_t size = (op->is_compressed()) ? 33 : 65;
        wl_vch_clear(pubkey);
        wl_vch_push_hex(pubkey,p->pubkey,size);
        return 0;
    }
    return -1;
}

int wl_key_pkdata(coin_t coin,const char *addr,vch_t *pkdata)
{
    struct wl_key_list *p = wl_key_find_list(coin,addr);
    if (p != NULL)
    {
        struct wl_coin_operation *op = wl_get_coin_operation(coin);
        size_t size = (op->is_compressed()) ? 33 : 65;
        wl_vch_clear(pkdata);
        wl_vch_push(pkdata,p->pubkey,size);
        return 0;
    }
    return -1;
}

int wl_key_sign(coin_t coin,const char *addr,const uint8_t *md32,vch_t *sig)
{
    struct wl_key_list *p = wl_key_find_list(coin,addr);
    if (p != NULL)
    {
        return wl_secp_sign_signature(p->secret,md32,sig);
    }
    return -1;
}


