// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "multicoin.h"

int lmc_test();
int eth_test();

void disp_str(char *s)
{
    printf("%s\n",s);
}

void disp_hex(void *s,int size)
{
    unsigned char *p = (unsigned char*)s;
    while(size--)
    {
        printf("%2.2x",*p++);
    }
    printf("\n");
}

void disp_json(const char *json_str)
{
    const char *sp = "                ";
    size_t s = strlen(sp);
    int indent = 0;
    const char *p = json_str;
    while (p && *p)
    {
        switch (*p)
        {
        case '{':
        case '[':
            indent += 2;
            printf("%c\n%s",*p,sp + (s - indent));
            break;
        case '}':
        case ']':
            indent -= 2;
            printf("\n%s%c",sp + (s - indent),*p);
            break;
        case ',':
            printf(",\n%s",sp + (s - indent));
            break;
        default:
            printf("%c",*p);
            break;
        }
        ++p;
    }
}

void disp_ver()
{
    vch_t *ver = wl_vch_new();
    if (wl_multicoin_version(ver) == 0)
    {
        printf("v%s\n",wl_vch_string(ver));
    }
    wl_vch_free(ver);
}

int createkey(coin_t coin)
{
    vch_t *address = wl_vch_new();
    vch_t *privkey = wl_vch_new();
    vch_t *pubkey  = wl_vch_new();

    printf("create key..\n");

    if (wl_multicoin_key_create(coin,address) < 0)
    {
        printf("failed to create key\n");
        return -1;
    }
    disp_str(wl_vch_string(address));

    if (wl_multicoin_key_privkey(coin,wl_vch_string(address),privkey) < 0)
    {
        printf("failed to get priv key\n");
        return -1;
    }
    disp_str(wl_vch_string(privkey));

    if (wl_multicoin_key_pubkey(coin,wl_vch_string(address),pubkey) < 0)
    {
        printf("failed to get pub key\n");
        return -1;
    }
    disp_str(wl_vch_string(pubkey));

    wl_vch_free(address);
    wl_vch_free(privkey);
    wl_vch_free(pubkey);
    return 0;
}

int importkey(coin_t coin,const char *privkey,const char *addr)
{
    vch_t *address = wl_vch_new();
    vch_t *pubkey  = wl_vch_new();

    printf("import key..\n");

    if (wl_multicoin_key_import(coin,privkey,address) < 0)
    {
        printf("failed to import key\n");
        return -1;
    }
    disp_str(wl_vch_string(address));

    if (wl_multicoin_key_pubkey(coin,wl_vch_string(address),pubkey) < 0)
    {
        printf("failed to get pub key\n");
        return -1;
    }
    disp_str(wl_vch_string(pubkey));

    if (wl_vch_cmp_string(address,addr) != 0)
    {
        printf("incorrect address\n");
        return -1;
    }

    wl_vch_free(address);
    wl_vch_free(pubkey);

    return 0;
}

int createscript(coin_t coin,const char *ctxt,const char *addr)
{
    vch_t *address = wl_vch_new();
    printf("create script...\n");
    if (wl_multicoin_script_addnew(coin,ctxt,address) < 0)
    {
        printf("failed to create script\n");
        return -1;
    }
    disp_str(wl_vch_string(address));
    if (wl_vch_cmp_string(address,addr) != 0)
    {
        printf("incorrect address\n");
        return -1;
    }
    wl_vch_free(address);
    return 0;
}

int parsetx(coin_t coin,const char *tx,const char *in)
{
    vch_t *json_str = wl_vch_new();
    if (wl_multicoin_tx_parse(coin,tx,in,json_str) < 0)
    {
        printf("failed to parse tx\n");
        wl_vch_free(json_str);
        return -1;
    }
    disp_json(wl_vch_string(json_str));
    wl_vch_free(json_str);
    return 0;
}

int signtx(coin_t coin,const char *tx,const char *in)
{
    vch_t *tx_signed = wl_vch_new();
    if (wl_multicoin_tx_sign(coin,tx,in,tx_signed) < 0)
    {
        printf("failed to sign tx\n");
        wl_vch_free(tx_signed);
        return -1;
    }
    disp_str(wl_vch_string(tx_signed));
    wl_vch_free(tx_signed);
    return 0;
}

int verifytx(coin_t coin,const char *tx,const char *in)
{
    vch_t *json_str = wl_vch_new();
    if (wl_multicoin_tx_verify(coin,tx,in,json_str) < 0)
    {
        printf("failed to verify tx\n");
        wl_vch_free(json_str);
        return -1;
    }
    disp_json(wl_vch_string(json_str));
    wl_vch_free(json_str);
    return 0;
}

int main(int argc,char **argv)
{
    wl_multicoin_init();

    disp_ver();
   
    if (!lmc_test())
    {
    }

    if (!eth_test())
    {
    }
    wl_multicoin_deinit();
    return 0;
}

