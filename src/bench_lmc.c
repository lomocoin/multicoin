#include <stdio.h>
#include "multicoin.h"

int createkey(coin_t coin);
int importkey(coin_t coin,const char *privkey,const char *addr);
int createscript(coin_t coin,const char *ctxt,const char *addr);
int parsetx(coin_t coin,const char *tx,const char *in);
int signtx(coin_t coin,const char *tx,const char *in);
int verifytx(coin_t coin,const char *tx,const char *in);


static const char *privkey = "cQ1rertRsLtFAGWTd32v6qsaPtQnedUe8nKYKZBFYxWPk6emfsyL";
static const char *address = "mhp2TEtL1AEWqVyAPcuuGswQTVyZrTFbVE";
//static const char *privkey2 = "cVy2kYCV7qvDrRE6zFd54yTDgQ9tULZPr2GtrQRSt2jw4kPMzMAa";
//static const char *address2 = "mtiBqUYHhxB2FEkyX5tHeN4woKDjb3bTNM";

static const char *multisig = "{\"type\":\"multisig\",\"param\":{\"req\":2,\"pubkeys\":["
                 "\"03fa56845825b1b3c25db5d69305867270d213ed7c8a126685a90b03433fcf695e\","
                 "\"036776b500d38f5ec2679f626102ca779a6e44ebc70bf282812717701e221e8dd8\","
                 "\"0278faa163e8dd4b0bf69560e6b9cf75204a2592d8dcf5d4e64962e869fdda83f8\"]"
                 "}}";
static const char *multisig_addr = "2N9DBEVW7Y83xKDg5onw8VuQ6PL3JJ6HHiH";
static const char *coldminting = "{\"type\":\"coldminting\",\"param\":{"
                                  "\"mint\":\"mtiBqUYHhxB2FEkyX5tHeN4woKDjb3bTNM\","
                                  "\"spent\":\"mhp2TEtL1AEWqVyAPcuuGswQTVyZrTFbVE\"}}";
static const char *coldminting_addr = "2NBk75UGzyxv6B6XcCha1EdnBUfQ5RVFN9s";

static const char *multisigcoldminting = "{\"type\":\"coldminting\",\"param\":{"
                                          "\"mint\":\"n26YGq7CdweqfgeeQetwu8ct651pvnftRT\","
                                          "\"spent\":\"2N9DBEVW7Y83xKDg5onw8VuQ6PL3JJ6HHiH\"}}";
static const char *multisigcoldminting_addr = "2N2PY2nHfwcC3u9fLTF7jMQ6ZxGrWo7bxy7";

static const char *tx1 = "010000001de5da5901f0e3d0bc26e149b32e18a14723a6e90fe9355446d8829048d942e235980e975f00000000484730440220124959e0844ef67eb9b4d92832d7d2334cf8e416d147b76346e974cfbaa8c7ae0220046c8f891fd045cfae5c7e105a6593adb2da9077427db5f41df400d888f6dab101ffffffff029c6de151720000001976a91447f281a7499351275a3d6d19013ce48b90af1a9788ac00ca9a3b0000000017a914cae88eeffc8b519f5a26455fadf56e004ba8ccec8700000000";
static const char *in1 = "[\"21034cbdecf541fbe7a1213f3f0262232c22467c20b4829ae588eaafb6b01265ad70ac\"]";
static const char *tx2 = "01000000bbe8da590145da9ae623936dbe46e8db3649f5cdabbf12660479b8f6ab4745865c475ac7b80100000000ffffffff0200e1f505000000001976a91400e9ef5b6e47f4baf6b4b656ffa98a166984137288ac9ce8a4350000000017a914644b85767ca04946d2308feb9e286c9b8c9490078700000000";
static const char *in2 = "[\"a914644b85767ca04946d2308feb9e286c9b8c94900787\"]";
static const char *tx3 = "01000000bbe8da590145da9ae623936dbe46e8db3649f5cdabbf12660479b8f6ab4745865c475ac7b801000000d300483045022100faf14bf926aa12c9dd6edca1bcb718040c89a2d2c7e5e149eb137bf483dae0cc02205697b1b0e167109424b689db032a590e3d96958824c1da5eeb692403a8fbd32c01004c86c06376a914e1bc9b4851ff035eef32f7baa5d45d42f97c761b88ac67522103fa56845825b1b3c25db5d69305867270d213ed7c8a126685a90b03433fcf695e21036776b500d38f5ec2679f626102ca779a6e44ebc70bf282812717701e221e8dd8210278faa163e8dd4b0bf69560e6b9cf75204a2592d8dcf5d4e64962e869fdda83f853ae68ffffffff0200e1f505000000001976a91400e9ef5b6e47f4baf6b4b656ffa98a166984137288ac9ce8a4350000000017a914644b85767ca04946d2308feb9e286c9b8c9490078700000000";
static const char *in3 = "[\"a914644b85767ca04946d2308feb9e286c9b8c94900787\"]";

static const char *tx4 = "01000000bbe8da590145da9ae623936dbe46e8db3649f5cdabbf12660479b8f6ab4745865c475ac7b801000000d300483045022100940a5968376bd9b73ebfb47a4480a81a9b3980fd8cab1c2d18609adcbf6eb26a0220308364e16b7c7fa10de71b37994676169ba57d9519da348a026255ee796b726c01004c86c06376a914e1bc9b4851ff035eef32f7baa5d45d42f97c761b88ac67522103fa56845825b1b3c25db5d69305867270d213ed7c8a126685a90b03433fcf695e21036776b500d38f5ec2679f626102ca779a6e44ebc70bf282812717701e221e8dd8210278faa163e8dd4b0bf69560e6b9cf75204a2592d8dcf5d4e64962e869fdda83f853ae68ffffffff0200e1f505000000001976a91400e9ef5b6e47f4baf6b4b656ffa98a166984137288ac9ce8a4350000000017a914644b85767ca04946d2308feb9e286c9b8c9490078700000000";
static const char *in4 = "[\"a914644b85767ca04946d2308feb9e286c9b8c94900787\"]";
static const char *tx5 = "01000000bbe8da590145da9ae623936dbe46e8db3649f5cdabbf12660479b8f6ab4745865c475ac7b801000000fd1b0100483045022100faf14bf926aa12c9dd6edca1bcb718040c89a2d2c7e5e149eb137bf483dae0cc02205697b1b0e167109424b689db032a590e3d96958824c1da5eeb692403a8fbd32c01483045022100940a5968376bd9b73ebfb47a4480a81a9b3980fd8cab1c2d18609adcbf6eb26a0220308364e16b7c7fa10de71b37994676169ba57d9519da348a026255ee796b726c014c86c06376a914e1bc9b4851ff035eef32f7baa5d45d42f97c761b88ac67522103fa56845825b1b3c25db5d69305867270d213ed7c8a126685a90b03433fcf695e21036776b500d38f5ec2679f626102ca779a6e44ebc70bf282812717701e221e8dd8210278faa163e8dd4b0bf69560e6b9cf75204a2592d8dcf5d4e64962e869fdda83f853ae68ffffffff0200e1f505000000001976a91400e9ef5b6e47f4baf6b4b656ffa98a166984137288ac9ce8a4350000000017a914644b85767ca04946d2308feb9e286c9b8c9490078700000000";
static const char *in5 = "[\"a914644b85767ca04946d2308feb9e286c9b8c94900787\"]";

int lmc_test()
{
    printf("==================== LMC BEGIN========================\n\n");
    
    /* */
    printf("create key test:\n");
    if (createkey(WALLEVE_COINS_LMC) < 0)
    {
        return -1;
    }
    printf("import key test:\n");
    if (importkey(WALLEVE_COINS_LMC,privkey,address) < 0)
    {
        return -1;
    }
    printf("create script test:\n");
    if (createscript(WALLEVE_COINS_LMC,multisig,multisig_addr) < 0)
    {
        return -1;
    }
    if (createscript(WALLEVE_COINS_LMC,coldminting,coldminting_addr) < 0)
    {
        return -1;
    }
    if (createscript(WALLEVE_COINS_LMC,multisigcoldminting,multisigcoldminting_addr) < 0)
    {
        return -1;
    }
    
    printf("parse tx test:\n");
    if (parsetx(WALLEVE_COINS_LMC,tx1,in1) < 0)
    {
        return -1;
    }
    if (parsetx(WALLEVE_COINS_LMC,tx5,in5) < 0)
    {
        return -1;
    }
    printf("sign tx test:\n");

    if (signtx(WALLEVE_COINS_LMC,tx2,in2) < 0)
    {
        return -1;
    }
    printf("\n");
    if (signtx(WALLEVE_COINS_LMC,tx3,in3) < 0)
    {
        return -1;
    }

    printf("verify tx test:\n");
    if (verifytx(WALLEVE_COINS_LMC,tx1,in1) < 0)
    {
        return -1;
    }
    printf("\n");
    if (verifytx(WALLEVE_COINS_LMC,tx4,in4) < 0)
    {
        return -1;
    }

    printf("\n");
    if (verifytx(WALLEVE_COINS_LMC,tx5,in5) < 0)
    {
        return -1;
    }

    printf("==================== LMC END========================\n\n");
    return 0; 
}

