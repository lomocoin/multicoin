#include <stdio.h>
#include "multicoin.h"

int createkey(coin_t coin);
int importkey(coin_t coin,const char *privkey,const char *addr);
int createscript(coin_t coin,const char *ctxt,const char *addr);
int parsetx(coin_t coin,const char *tx,const char *in);
int signtx(coin_t coin,const char *tx,const char *in);
int verifytx(coin_t coin,const char *tx,const char *in);

static const char *privkey = "edea87d412074344443a5279248eadb6acbad636d46a60982c729adf8b0cda68";
static const char *address = "0017bcd4d9edb2cc0d751126bde47e64f971d7d3";
static const char *tx1 = "{\"hex\":\"f86d80018259d894095e7baea6a6c7c4c2dfeb977efac326af552d870a8e0358ac39584bc98a7c979f984b031ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804\"}";
static const char *ctxt1 = "{\"from\":\"0017bcd4d9edb2cc0d751126bde47e64f971d7d3\"}";
static const char *tx2 = "{\"data\" : \"\",\"gas\" : \"5208\",\"price\" : \"01\",\"nonce\" : \"00\","
                          "\"r\" : \"98ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4a\","
                          "\"s\" : \"8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3\","
                          "\"to\" : \"000000000000000000000000000b9331677e6ebf\","
                          "\"v\" : \"1c\",\"value\" : \"0a\"}";
static const char *tx3 = "{\"hex\":\"f86d80018259d894095e7baea6a6c7c4c2dfeb977efac326af552d870a8e0358ac39584bc98a7c979f984b031ba0037e7a0805cf2ff3e302f542f3b492b1365e467f2ea0ba320ec1e1017b9c239ea002e50a58fb5eadbd53d5a5db47e7fb092dcdcf925699ee94c161bc2f350d69cd\"}";
static const char *ctxt3 = "{\"from\":\"0017bcd4d9edb2cc0d751126bde47e64f971d7d3\"}";
int eth_test()
{
    printf("==================== ETH BEGIN========================\n\n");

    /* */

    printf("create key test:\n");
    if (createkey(WALLEVE_COINS_ETH) < 0)
    {
        return -1;
    }

    printf("import key test:\n");
    if (importkey(WALLEVE_COINS_ETH,privkey,address) < 0)
    {
        return -1;
    }

    printf("parse tx test:\n");

    if (parsetx(WALLEVE_COINS_ETH,tx1,NULL) < 0)
    {
        return -1;
    }

    if (parsetx(WALLEVE_COINS_ETH,tx2,NULL) < 0)
    {
        return -1;
    }

    printf("sign tx test:\n");
    if (signtx(WALLEVE_COINS_ETH,tx1,ctxt1) < 0)
    {
        return -1;
    }

    printf("verify tx test:\n");
    if (verifytx(WALLEVE_COINS_ETH,tx3,ctxt3) < 0)
    {
        return -1;
    }

    printf("==================== ETH END========================\n\n");
    return 0;
}

int eth_test0()
{
    vch_t *addr = wl_vch_new();
    vch_t *pubkey  = wl_vch_new();
    vch_t *json_str = wl_vch_new();
    char *privkey0 = "816680718cceecedbf5d04b994e3d46c9be6f208629b0209083d3bc246208fa7";
    char *tx = "{\"data\" : \"c6427474000000000000000000000000afe0be9d8c967cefc87bb9e12a6f3bce4ea15455000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000d4dcb6303b900d08328ab1a52ad54e352c2b8e97000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000\","
	                      "\"gas\" : \"2a349\",\"price\" : \"c845880\",\"nonce\" : \"a\","
                          "\"r\" : \"0\","
                          "\"s\" : \"0\","
                          "\"to\" : \"bfe523bfa0b5f2f2676704b2eef455aaf344a1a4\","
                          "\"v\" : \"0\","
                          "\"value\" : \"0\"}";

    if (wl_multicoin_key_import(WALLEVE_COINS_ETH,privkey0,addr) < 0)
    {
        printf("failed to import key\n");
        return -1;
    }
    printf("addr:%s\n", wl_vch_string(addr));

    if (wl_multicoin_key_pubkey(WALLEVE_COINS_ETH,wl_vch_string(addr),pubkey) < 0)
    {
        printf("failed to get pub key\n");
        return -1;
    }
    printf("pubkey:%s\n", wl_vch_string(pubkey));

    char in[200] = {"\0"};
    sprintf(in, "{\"from\": \"%s\"}", wl_vch_string(addr));

    if (wl_multicoin_tx_parse(WALLEVE_COINS_ETH,tx,in,json_str) < 0)
    {
        printf("failed to parse tx\n");
        wl_vch_free(json_str);
        return -1;
    }
    printf("json:%s\n", wl_vch_string(json_str));

    vch_t *tx_signed = wl_vch_new();
    if (wl_multicoin_tx_sign(WALLEVE_COINS_ETH,tx,in,tx_signed) < 0)
    {
        printf("failed to sign tx\n");
        wl_vch_free(tx_signed);
        return -1;
    }
    printf(">sign:%s\n", wl_vch_string(tx_signed));

    char tx01[1014] = {'\0'};
    sprintf(tx01, "{\"hex\": \"%s\"}", wl_vch_string(tx_signed));

    vch_t *json_str1 = wl_vch_new();
    if (wl_multicoin_tx_verify(WALLEVE_COINS_ETH, tx01,in,json_str1) < 0)
    {
        printf("failed to verify tx\n");
        wl_vch_free(json_str1);
        return -1;
    }
    printf("verify:%s\n", wl_vch_string(json_str1));

    // char tx02[1024] = {'\0'};
    // char in02[1024] = {'\0'};
    // sprintf(tx02, "{\"hex\":\"%s\"}", wl_vch_string(tx_signed));
    // sprintf(in02, "{\"from\":\"%s\"}", wl_vch_string(addr));
    // vch_t *json_str2 = wl_vch_new();
    // if (wl_multicoin_tx_parse(WALLEVE_COINS_ETH,tx02,in02,json_str2) < 0)
    // {
    //     printf("failed to parse tx\n");
    //     wl_vch_free(json_str2);
    //     return -1;
    // }
    // printf("end json:%s\n", wl_vch_string(json_str2));


    wl_vch_free(json_str);
    wl_vch_free(tx_signed);
    wl_vch_free(addr);
    wl_vch_free(pubkey);
    wl_vch_free(json_str1);

    return 0;
}