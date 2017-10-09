// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
    
#ifndef  WALLEVE_JSON_H
#define  WALLEVE_JSON_H

#include <stdlib.h>
#include <stdint.h>

#include "vch.h"

typedef enum 
{
    WL_JSON_NULL = 0,
    WL_JSON_OBJECT,
    WL_JSON_ARRAY,
    WL_JSON_STRING,
    WL_JSON_INTEGER,
    WL_JSON_FLOAT,
    WL_JSON_BOOLEAN,
}json_type;

typedef struct json 
{
    struct json *next;
    json_type type;
    vch_t * name;
    union
    {
        struct json *list;
        vch_t *s;
        int64_t i;
        double d;
        int b;
    } value;
}json_t;

json_t *wl_json_new(const char *name,json_type type);
json_t *wl_json_new_string(const char *name,const char *value);
json_t *wl_json_new_integer(const char *name,int64_t value);
json_t *wl_json_new_float(const char *name,double value);
json_t *wl_json_new_boolean(const char *name,int value);
void wl_json_free(json_t *json);

json_t *wl_json_insert(json_t *json,json_t *jnew);
json_t *wl_json_find(json_t *json,const char *name);
    
int wl_json_tostring(json_t *json,vch_t *vch);
json_t *wl_json_fromstring(const char *str);

inline int wl_json_is_string(json_t *json)
{
    return (json->type == WL_JSON_STRING);
}

inline char *wl_json_get_string(json_t *json)
{
    return (json->type == WL_JSON_STRING ? wl_vch_string(json->value.s) : NULL);
}

inline int wl_json_is_number(json_t *json)
{
    return (json->type == WL_JSON_INTEGER || json->type == WL_JSON_FLOAT);
}

inline int64_t wl_json_get_integer(json_t *json)
{
    return (json->type == WL_JSON_INTEGER ? json->value.i :
             (json->type == WL_JSON_FLOAT ? (int64_t)json->value.d : 0));
}

inline double wl_json_get_double(json_t *json)
{
    return (json->type == WL_JSON_FLOAT ? json->value.d :
             (json->type == WL_JSON_INTEGER ? (double)json->value.i : 0.0));
}

inline int wl_json_is_boolean(json_t *json)
{
    return (json->type == WL_JSON_BOOLEAN);
}

inline int wl_json_get_boolean(json_t *json)
{
    return (json->type == WL_JSON_BOOLEAN ? json->value.b : 0);
}

inline int wl_json_is_object(json_t *json)
{
    return (json->type == WL_JSON_OBJECT);
}

inline int wl_json_is_array(json_t *json)
{
    return (json->type == WL_JSON_ARRAY);
}

inline json_t *wl_json_array_first(json_t *json)
{
    return (json->type == WL_JSON_ARRAY ? json->value.list : NULL);
}

inline json_t *wl_json_array_next(json_t *item)
{
    return item->next;
}

#endif //WALLEVE_JSON_H
