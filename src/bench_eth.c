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
