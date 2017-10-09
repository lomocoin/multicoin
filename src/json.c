// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "json.h"
    
#define JSONSTR_TRIM(p) while(*(p) == ' ' || *(p) == '\n') (p)++;

json_t *wl_json_new(const char *name,json_type type)
{
    json_t *json = (json_t*)calloc(1,sizeof(json_t));
    if (json != NULL)
    {
        json->type = type;

        if (name != NULL)
        {
            if ((json->name = wl_vch_new_str(name)) == NULL)
            {
                wl_json_free(json);
                json = NULL;
            }
        }
    }
    return json;
}

json_t *wl_json_new_string(const char *name,const char *value)
{
    json_t *json = wl_json_new(name,WL_JSON_STRING);
    if (json != NULL)
    {        
        if ((json->value.s = wl_vch_new_str(value)) == NULL)
        {
            wl_json_free(json);
            json = NULL;
        }
    }
    return json;
}

json_t *wl_json_new_integer(const char *name,int64_t value)
{
    json_t *json = wl_json_new(name,WL_JSON_INTEGER);
    if (json != NULL)
    {
        json->value.i = value;
    }
    return json;
}

json_t *wl_json_new_float(const char *name,double value)
{
    json_t *json = wl_json_new(name,WL_JSON_FLOAT);
    if (json != NULL)
    {
        json->value.d = value;
    }
    return json;
}

json_t *wl_json_new_boolean(const char *name,int value)
{
    json_t *json = wl_json_new(name,WL_JSON_BOOLEAN);
    if (json != NULL)
    {
        json->value.b = value;
    }
    return json;
}

static inline void wl_json_free_list(json_t *list)
{
    while (list != NULL)
    {
        json_t * json = list;
        list = json->next;
        wl_json_free(json);
    }
}

void wl_json_free(json_t *json)
{
    if (json != NULL)
    {
        wl_vch_free(json->name);
        switch (json->type)
        {
        case WL_JSON_OBJECT:
        case WL_JSON_ARRAY:
            wl_json_free_list(json->value.list);
            break;
        case WL_JSON_STRING:
            wl_vch_free(json->value.s);
            break;
        default:
            break;
        }
        free(json);
    }
}

json_t *wl_json_insert(json_t *json,json_t *jnew)
{
    if (jnew == NULL)
    {
        return NULL;
    }

    if (json->type != WL_JSON_OBJECT && json->type != WL_JSON_ARRAY)
    {
        wl_json_free(jnew);
        return NULL;
    }

    jnew->next = NULL;
    if (json->value.list == NULL)
    {
        json->value.list = jnew;
    }
    else 
    {
        json_t *prev = json->value.list;
        while (prev->next != NULL)
        {
            prev = prev->next;
        }
        prev->next = jnew;
    }
    
    return jnew;
}

json_t *wl_json_find(json_t *json,const char *name)
{
    if (json != NULL && json->type == WL_JSON_OBJECT)
    {
        json_t *item = json->value.list;
        while (item != NULL)
        {
            if (wl_vch_cmp_string(item->name,name) == 0)
            {
                return item;
            }
            item = item->next;
        }
    }
    return NULL;
}

static void wl_json_formatstr(json_t *json,vch_t *vch);
static void wl_json_formatlist(json_t *list,vch_t *vch)
{
    while (list != NULL)
    {
        wl_json_formatstr(list,vch);
        list = list->next;
        if (list != NULL)
        {
            wl_vch_push_string(vch,",");
        }
    }
}

static void wl_json_formatstr(json_t *json,vch_t *vch)
{
    if (json->name != NULL)
    {
        wl_vch_push_sprintf(vch,"\"%s\":",wl_vch_string(json->name));
    }

    switch (json->type)
    {
    case WL_JSON_OBJECT:
        wl_vch_push_string(vch,"{");
        wl_json_formatlist(json->value.list,vch);
        wl_vch_push_string(vch,"}");
        break;
    case WL_JSON_ARRAY:
        wl_vch_push_string(vch,"[");
        wl_json_formatlist(json->value.list,vch);
        wl_vch_push_string(vch,"]");
        break;
    case WL_JSON_STRING:
        wl_vch_push_sprintf(vch,"\"%s\"",wl_vch_string(json->value.s));
        break;
    case WL_JSON_INTEGER:
        wl_vch_push_sprintf(vch,"%ld",json->value.i);
        break; 
    case WL_JSON_FLOAT:
        wl_vch_push_sprintf(vch,"%.10f",json->value.d);
        break;
    case WL_JSON_BOOLEAN:
        wl_vch_push_string(vch,json->value.b ? "true" : "false");
        break;
    default:
        break;
    }
}

int wl_json_tostring(json_t *json,vch_t *vch)
{
    if (json->type != WL_JSON_OBJECT && json->type != WL_JSON_ARRAY)
    {
        return -1;
    }
    
    wl_json_formatstr(json,vch);
    wl_vch_push_string(vch,"\n");
    return 0;
}


static inline vch_t *wl_json_extract_string(const char *start,const char **endp)
{
    vch_t *vch = NULL;
    const char *p = ++start;
    while (*p != '\0')
    {
        if (*p == '"')
        {
            if ((vch = wl_vch_new()) != NULL)
            {
                if (wl_vch_push(vch,(const uint8_t*)start,p - start) < 0)
                {
                    wl_vch_free(vch);
                    vch = NULL;
                }
            }
            *endp = p + 1;
            break;
        }
        p++;
    }
    return vch;
}

static inline int wl_json_is_delimiter(const char c)
{
    return (c == '}' || c == ']' || c == ',' || c == '\0');
}

static inline const char *wl_json_find_delimiter(const char *p)
{
    if (p == NULL)
    {
        return NULL;
    }
    JSONSTR_TRIM(p);
    return (wl_json_is_delimiter(*p) ? p : NULL);
}

static json_t *wl_json_parse(const char *start,const char **endp);
static json_t *wl_json_parse_object(const char *name,const char *start,const char **endp)
{
    const char *end = NULL;
    json_t *item = NULL;
    json_t *json = wl_json_new(name,WL_JSON_OBJECT);
    if (json == NULL)
    {
        return NULL;
    }

    if ((end = wl_json_find_delimiter(++start)) != NULL)
    {
        if (*end != '}' || (*endp = wl_json_find_delimiter(end + 1)) == NULL)
        {
            wl_json_free(json);
            json = NULL;
        }
        return json;
    }

    while ((item = wl_json_insert(json,wl_json_parse(start,&end))) != NULL 
           && item->name != NULL)
    {
        if (*end == ',')
        {
            start = end + 1;
        }
        else if (*end == '}' && (*endp = wl_json_find_delimiter(end + 1)) != NULL)
        {
            return json;
        }
        else
        {
            break;
        }
    }

    wl_json_free(json);
    return NULL;
}

static json_t *wl_json_parse_array(const char *name,const char *start,const char **endp)
{
    const char *end = NULL;
    json_t *item = NULL;
    json_t *json = wl_json_new(name,WL_JSON_ARRAY);
    if (json == NULL)
    {
        return NULL;
    }

    if ((end = wl_json_find_delimiter(++start)) != NULL)
    {
        if (*end != ']' || (*endp = wl_json_find_delimiter(end + 1)) == NULL)
        {
            wl_json_free(json);
            json = NULL;
        }
        return json;
    }

    while ((item = wl_json_insert(json,wl_json_parse(start,&end))) != NULL 
           && item->name == NULL)
    {
        if (*end == ',')
        {
            start = end + 1;
        }
        else if (*end == ']' && (*endp = wl_json_find_delimiter(end + 1)) != NULL)
        {
            return json;
        }
        else
        {
            break;
        }
    }

    wl_json_free(json);
    return NULL;
    
}

static json_t *wl_json_parse_string(const char *name,const char *start,const char **endp)
{
    json_t *json = NULL;
    const char *end = NULL;
    vch_t *vch = wl_json_extract_string(start,&end);
    if (vch == NULL || (*endp = wl_json_find_delimiter(end)) == NULL)
    {
        return NULL;
    }
    json = wl_json_new_string(name,wl_vch_string(vch));
    wl_vch_free(vch);
    return json;
}

static json_t *wl_json_parse_number(const char *name,const char *start,const char **endp)
{
    char *end = NULL;
    double d = strtod(start,&end);
    if (end == NULL || (*endp = wl_json_find_delimiter(end)) == NULL)
    {
        return NULL;
    }
    else 
    {
        int64_t i = strtoll(start,&end,10);
        if (*end != '.')
        {
            return wl_json_new_integer(name,i);
        }
    }
    return wl_json_new_float(name,d);
}

static json_t *wl_json_parse_token(const char *name,const char *start,const char **endp)
{
    const char *end = NULL;
    int token = -1;
    if (strncmp(start,"true",4) == 0)
    {
        end = start + 4;
        token = 1;
    }
    else if (strncmp(start,"false",5) == 0)
    {
        end = start + 5;
        token = 0;
    }
    else if (strncmp(start,"null",4) == 0)
    {
        end = start + 4;
        token = -1;
    }

    if ((*endp = wl_json_find_delimiter(end)) == NULL)
    {
        return NULL;    
    }

    if (token < 0)
    {
        return wl_json_new(name,WL_JSON_NULL);
    }
    return wl_json_new_boolean(name,token);
}

static json_t *wl_json_parse_value(const char *name,const char *start,const char **endp)
{
    JSONSTR_TRIM(start);
    switch (*start)
    {
    case 't':
    case 'f':
    case 'n':
        return wl_json_parse_token(name,start,endp);
    case '{':
        return wl_json_parse_object(name,start,endp);
    case '[':
        return wl_json_parse_array(name,start,endp);
    case '"':
        return wl_json_parse_string(name,start,endp);
    default:
        break;
    }
    return wl_json_parse_number(name,start,endp);
}

static json_t *wl_json_parse(const char *start,const char **endp)
{
    json_t *json = NULL;
    vch_t *vch = NULL;

    JSONSTR_TRIM(start);

    if (*start == '"')
    {
        if ((vch = wl_json_extract_string(start,endp)) != NULL)
        {
            const char *sp = *endp;
            JSONSTR_TRIM(sp);
            if (*sp == ':')
            {
                start = sp + 1;
            }
            else
            {
                json = wl_json_new_string(NULL,wl_vch_string(vch));
                wl_vch_free(vch);
                return json;
            }
        }
        else
        {
            return NULL;
        }
    }
    
    json = wl_json_parse_value(wl_vch_string(vch),start,endp);
    wl_vch_free(vch);
    return json;
}

json_t *wl_json_fromstring(const char *str)
{
    const char *end = NULL;
    json_t *json = wl_json_parse(str,&end);
    if (json != NULL && (end == NULL || *end != '\0' 
                        || (json->type != WL_JSON_OBJECT && json->type != WL_JSON_ARRAY)))
    {
        wl_json_free(json);
        json = NULL;
    }
    return json;
}
