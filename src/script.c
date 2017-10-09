// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>
#include "script.h"

struct wl_script_list
{
    struct wl_script_list *next;
    vch_t *scriptid;
    vch_t *script;
};

static struct wl_script_list *_script_list[WALLEVE_COINS_COUNT] = {NULL,};

static inline void wl_script_free_list(struct wl_script_list *p);

static inline struct wl_script_list *wl_script_new_list()
{
    struct wl_script_list *p = (struct wl_script_list *)calloc(1,sizeof(struct wl_script_list)); 
    if (p != NULL)
    {
        if ((p->script = wl_vch_new()) == NULL || (p->scriptid = wl_vch_new()) == NULL)
        {
            wl_script_free_list(p);
            p = NULL;
        }
    }
    return p;
}

static inline void wl_script_free_list(struct wl_script_list *p)
{
    if (p != NULL)
    {
        if (p->scriptid != NULL)
        {
            wl_vch_free(p->scriptid);
        }
        if (p->script != NULL)
        {
            wl_vch_free(p->script);
        }
        free(p);
    }
}

static inline void wl_script_insert_list(coin_t coin,struct wl_script_list *p)
{
    p->next = _script_list[coin];
    _script_list[coin] = p;
}

static inline void wl_script_remove_list(coin_t coin,const char *scriptid)
{
    struct wl_script_list *p = _script_list[coin];
    struct wl_script_list *q = NULL;
    while(p != NULL)
    {
        if (wl_vch_cmp_string(p->scriptid,scriptid) == 0)
        {
            if (q != NULL)
            {
                q->next = p->next;
            }
            else
            {
                _script_list[coin] = p->next;
            }
            wl_script_free_list(p);
            break;
        } 
        q = p;p = p->next;
    }
}

static inline struct wl_script_list *wl_script_find_list(coin_t coin,const char *scriptid)
{
    struct wl_script_list *p = _script_list[coin];
    while(p != NULL)
    {
        if (wl_vch_cmp_string(p->scriptid,scriptid) == 0)
        {
            break;
        }
        p = p->next;
    }
    return p;
}

void wl_script_init()
{
}

void wl_script_clear()
{
    int i;
    struct wl_script_list *q,*p;

    for (i = 0;i < WALLEVE_COINS_COUNT;i++)
    {
        p = _script_list[i];
        while(p != NULL)
        {
            q = p;p = p->next;
            wl_script_free_list(q);
        }
        _script_list[i] = NULL;
    }
}

int wl_script_addnew(coin_t coin,const char *context,vch_t *scriptid)
{
    struct wl_script_list *p = wl_script_new_list(); 
    if (p != NULL)
    {
        if (wl_get_coin_operation(coin)->build_script(context,p->script,p->scriptid) == 0)
        {
            if (wl_vch_copy(scriptid,p->scriptid) == 0)
            {
                wl_script_remove_list(coin,wl_vch_string(p->scriptid));
                wl_script_insert_list(coin,p);
                return 0;
            }
            else
            {
                wl_script_free_list(p);
            }
        }
    }
    return -1;
}

void wl_script_remove(coin_t coin,const char *scriptid)
{
    wl_script_remove_list(coin,scriptid);
}

int wl_script_export(coin_t coin,const char *scriptid,vch_t *script)
{
    struct wl_script_list *p = wl_script_find_list(coin,scriptid);
    if (p != NULL)
    {
        return wl_vch_copy(script,p->script);
    }
    return -1;
}


