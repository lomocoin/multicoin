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

    printf("==================== ETH END========================\n\n");
    return 0;
}
