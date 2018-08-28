#include <stdio.h>
#include "multicoin.h"
#include "biguint.h"

int createkey(coin_t coin);
int importkey(coin_t coin,const char *privkey,const char *addr);
int createscript(coin_t coin,const char *ctxt,const char *addr);
int parsetx(coin_t coin,const char *tx,const char *in);
int signtx(coin_t coin,const char *tx,const char *in);
int verifytx(coin_t coin,const char *tx,const char *in);

// static const char *privkey = "cQ1rertRsLtFAGWTd32v6qsaPtQnedUe8nKYKZBFYxWPk6emfsyL";
// static const char *address = "mhp2TEtL1AEWqVyAPcuuGswQTVyZrTFbVE";

static const char *privkey = "cScf3yexWksXTABRzYBbukVN6PFe9Xbz7r1EsvnhcFvoPVuGmzwR";
static const char *address = "mhLMTeySgC69mjtz9xAmdnshQ8tVxxF49E";

static const char *multisig = "{\"type\":\"multisig\",\"param\":{\"req\":2,\"pubkeys\":["
                 "\"03fa56845825b1b3c25db5d69305867270d213ed7c8a126685a90b03433fcf695e\","
                 "\"036776b500d38f5ec2679f626102ca779a6e44ebc70bf282812717701e221e8dd8\","
                 "\"0278faa163e8dd4b0bf69560e6b9cf75204a2592d8dcf5d4e64962e869fdda83f8\"]"
                 "}}";
static const char *multisig_addr = "2N9DBEVW7Y83xKDg5onw8VuQ6PL3JJ6HHiH";

static const char *tx1 = "0100000001fdded3dc0b37f12c4e7523b5d471aed32a4791433c434fc28bed69bb6935f5d90000000000ffffffff020065cd1d000000001976a9143633b65fb9a31607f2c114cf6b6fbb7aed5a484f88ac58557307000000001976a91423a6a68c424a973d0201774169ab931477bb44e088ac00000000";
static const char *in1 = "[\"21038f29408e91c6550f32fac54f7ab89a405b1072302199b08fe2242305aa19eb32ac\"]";

static const char *tx1_sign = "0100000001fdded3dc0b37f12c4e7523b5d471aed32a4791433c434fc28bed69bb6935f5d9000000004847304402206aae479d209183c4c7f7772a4e4cb738c8af39b38b0cbde224f3b76f5f21f62a02202521d27da6400f882b03be0c7913ab5cffd685823f8796bb145d3c9cb1b7eb9901ffffffff020065cd1d000000001976a9143633b65fb9a31607f2c114cf6b6fbb7aed5a484f88ac58557307000000001976a91423a6a68c424a973d0201774169ab931477bb44e088ac00000000";

int btc_test2() {
    printf("------------------------------BTC BEGIN-----------------------\n\n");
    // char *tx01 = "0100000001bb7e20482254a0276f35129539ebde5b8607e64dc93eeb4788f77ff92f4f054f0000000000ffffffff01c0d60854020000001976a91483ddbeecd3fcdaa065ad07cf4c62932226cb7d9088ac00000000";
    char *tx01 = "0100000001bb7e20482254a0276f35129539ebde5b8607e64dc93eeb4788f77ff92f4f054f00000000b5004730440220360525125cb69ae5be192ab1877515d7dd7658b1fb2b2f8d3c2f245f8294450502204f3cc9e38840dc9f0e1225634f46fef9bca37efa4cd24a4f9b443d80e1df5bf701004c69522103af719a35c838f0d6573d652bcc7993b7af1ed55a431b65608a7452cd67f52d79210242ce7f05e4d15477cdc687a626e677fb3cfce4c5922e64665f66e1d355fca7522103685e4d05ce1229cba687548a66475db52beec546bec36caab448b26c8a7ae44653aeffffffff01c0d60854020000001976a91483ddbeecd3fcdaa065ad07cf4c62932226cb7d9088ac00000000";
    char *sp01 = "[\"a9140392854142e6f94e3e06763ebc917cde1ab88f7587\"]";

    char multisig1[1024] = {'\0'};
    vch_t *script_addr = wl_vch_new();
    vch_t *script_export = wl_vch_new();
    // sprintf(multisig1, "{\"type\":\"multisig\", \"param\":{\"req\":%d, \"pubkeys\":[\"%s\", \"%s\", \"%s\"]}}", 2, wl_vch_string(pubkey1), wl_vch_string(pubkey2), wl_vch_string(pubkey3));
    char *pk1 = "03af719a35c838f0d6573d652bcc7993b7af1ed55a431b65608a7452cd67f52d79";
    char *pk2 = "0242ce7f05e4d15477cdc687a626e677fb3cfce4c5922e64665f66e1d355fca752";
    char *pk3 = "03685e4d05ce1229cba687548a66475db52beec546bec36caab448b26c8a7ae446";
    sprintf(multisig1, "{\"type\":\"multisig\", \"param\":{\"req\":%d, \"pubkeys\":[\"%s\", \"%s\", \"%s\"]}}", 2, pk1, pk2, pk3);
    wl_multicoin_script_addnew(WALLEVE_COINS_BTC, multisig1, script_addr);

    vch_t *addr1 = wl_vch_new();
    char *privkey1 = "cPB68AzJtfPamJWmyHCLgH1VDScJQhhg3XcRtp3LxEmWxLhrt6ry";
    vch_t *pubkey1 = wl_vch_new();
    wl_multicoin_key_import(WALLEVE_COINS_BTC,privkey1,addr1);
    wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr1), pubkey1);
    printf("addr:%s\n", wl_vch_string(addr1));
    printf("pubkey:%s\n", wl_vch_string(pubkey1));

    // vch_t *addr2 = wl_vch_new();
    // char *privkey2 = "cUccgVDCNz7VEDVqWtBY2VFbhVCc44aL3W85DmkXDPr5H1XovnRx";
    // vch_t *pubkey2 = wl_vch_new();
    // wl_multicoin_key_import(WALLEVE_COINS_BTC, privkey2, addr2);
    // wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr2), pubkey2);
    // printf("addr:%s\n", wl_vch_string(addr2));
    // printf("pubkey:%s\n", wl_vch_string(pubkey2));

    // vch_t *addr3 = wl_vch_new();
    // char *privkey3 = "cUvjeqKUyB4GnYEQ9iQpFgZHKx68ner7oTLn2g2ghUtrS35kXggg";
    // vch_t *pubkey3 = wl_vch_new();
    // wl_multicoin_key_import(WALLEVE_COINS_BTC, privkey3, addr3);
    // wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr3), pubkey3);
    // printf("addr:%s\n", wl_vch_string(addr3));
    // printf("pubkey:%s\n", wl_vch_string(pubkey3));

    vch_t *tx_signed01 = wl_vch_new();
    wl_multicoin_tx_sign(WALLEVE_COINS_BTC, tx01, sp01, tx_signed01);
    printf("[2] sign:%s\n", wl_vch_string(tx_signed01));

    vch_t *ret_json01 = wl_vch_new();
    wl_multicoin_tx_verify(WALLEVE_COINS_BTC, wl_vch_string(tx_signed01), sp01, ret_json01);
    printf("[3] verify:%s", wl_vch_string(ret_json01));
    printf("------------------------------BTC END-----------------------\n\n");

    return 0;
}

int btc_test1()
{
    printf("------------------------------BTC BEGIN-----------------------\n\n");
    printf("/*----------交易1：向多签地址打款*/\n");
    vch_t *addr4 = wl_vch_new();
    char *privkey4 = "cMmjAhs2WVWuKNmPSfDcJYYhVeUYZnqzDkaAUHAyA8fg4F6B8ahJ";
    vch_t *pubkey4 = wl_vch_new();
    wl_multicoin_key_import(WALLEVE_COINS_BTC, privkey4, addr4);
    wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr4), pubkey4);
    printf("addr:%s\n", wl_vch_string(addr4));
    printf("pubkey:%s\n", wl_vch_string(pubkey4));

    char *tx00 = "0100000001fd07772f917bcf5c9f1a7c67e836cd34d436bd982e2b33895c8954c5bb56ed9d0000000000ffffffff017055814a0000000017a914813f85b57bd50a5bff5e5008fdfe22445e9333108700000000";
    char *sp00 = "[\"210315cc2cb8e26e356d8a15cfb176ba3a41ad86d8aa0be745a196ffaeac189139d0ac\"]";
    vch_t *tx_json00 = wl_vch_new();
    wl_multicoin_tx_parse(WALLEVE_COINS_BTC, tx00, sp00, tx_json00);
    printf("[1] parse:%s", wl_vch_string(tx_json00));

    vch_t *tx_signed00 = wl_vch_new();
    wl_multicoin_tx_sign(WALLEVE_COINS_BTC, tx00, sp00, tx_signed00);
    printf("[2] sign:%s\n", wl_vch_string(tx_signed00));

    vch_t *ret_json00 = wl_vch_new();
    wl_multicoin_tx_verify(WALLEVE_COINS_BTC, wl_vch_string(tx_signed00), sp00, ret_json00);
    printf("[3] verify:%s", wl_vch_string(ret_json00));
    printf("/*----------交易1：结束*/\n");

    printf("/*----------交易2：多签地址向其他地址付款*/\n");
    char *tx01 = "0100000001ddf59f412bcc6255b74c9230378b3bc6e1f4094c242dfb04a2016ed008143e4c0000000000ffffffff01602e814a000000001976a914142630aa5dff93bc02668ddd45fef44f3c56843f88ac00000000";
    char *sp01 = "[\"a914813f85b57bd50a5bff5e5008fdfe22445e93331087\"]";
    vch_t *tx_json01 = wl_vch_new();
    wl_multicoin_tx_parse(WALLEVE_COINS_BTC, tx01, sp01, tx_json01);
    printf("[1] parse:%s", wl_vch_string(tx_json01));

    vch_t *addr1 = wl_vch_new();
    char *privkey1 = "cP6CbCYSdcwtEgr8mYa1BWY1gytppicNTnpdVBKPCK4LRnDS1N4D";
    vch_t *pubkey1 = wl_vch_new();
    wl_multicoin_key_import(WALLEVE_COINS_BTC,privkey1,addr1);
    wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr1), pubkey1);
    printf("addr:%s\n", wl_vch_string(addr1));
    printf("pubkey:%s\n", wl_vch_string(pubkey1));

    char multisig1[1024] = {'\0'};
    vch_t *script_addr = wl_vch_new();
    vch_t *script_export = wl_vch_new();
    // sprintf(multisig1, "{\"type\":\"multisig\", \"param\":{\"req\":%d, \"pubkeys\":[\"%s\", \"%s\", \"%s\"]}}", 2, wl_vch_string(pubkey1), wl_vch_string(pubkey2), wl_vch_string(pubkey3));
    char *pk1 = "027f35b748e588b281bacada05d30a4ae9738ef1e5d5b8eaccba8a2cf7ae8db215";
    char *pk2 = "0207eb3297e0ce22fbf0b441fd509ba1c7971a5de2f19ba8035075888940642a29";
    char *pk3 = "02ab6b5f58b5460a181c88c62bdd1f2245e706d2414afa63786d1a8f4f373f6853";
    sprintf(multisig1, "{\"type\":\"multisig\", \"param\":{\"req\":%d, \"pubkeys\":[\"%s\", \"%s\", \"%s\"]}}", 2, pk1, pk2, pk3);
    wl_multicoin_script_addnew(WALLEVE_COINS_BTC, multisig1, script_addr);

    vch_t *tx_signed01 = wl_vch_new();
    wl_multicoin_tx_sign(WALLEVE_COINS_BTC, tx01, sp01, tx_signed01);
    printf("[2] sign:%s\n", wl_vch_string(tx_signed01));

    vch_t *ret_json01 = wl_vch_new();
    wl_multicoin_tx_verify(WALLEVE_COINS_BTC, wl_vch_string(tx_signed01), sp01, ret_json01);
    printf("[3] verify:%s", wl_vch_string(ret_json01));

    // vch_t *addr2 = wl_vch_new();
    // char *privkey2 = "cUccgVDCNz7VEDVqWtBY2VFbhVCc44aL3W85DmkXDPr5H1XovnRx";
    // vch_t *pubkey2 = wl_vch_new();
    // wl_multicoin_key_import(WALLEVE_COINS_BTC, privkey2, addr2);
    // wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr2), pubkey2);
    // printf("addr:%s\n", wl_vch_string(addr2));
    // printf("pubkey:%s\n", wl_vch_string(pubkey2));

    vch_t *addr3 = wl_vch_new();
    char *privkey3 = "cUvjeqKUyB4GnYEQ9iQpFgZHKx68ner7oTLn2g2ghUtrS35kXggg";
    vch_t *pubkey3 = wl_vch_new();
    wl_multicoin_key_import(WALLEVE_COINS_BTC, privkey3, addr3);
    wl_multicoin_key_pubkey(WALLEVE_COINS_BTC, wl_vch_string(addr3), pubkey3);
    printf("addr:%s\n", wl_vch_string(addr3));
    printf("pubkey:%s\n", wl_vch_string(pubkey3));

    vch_t *tx_signed02 = wl_vch_new();
    wl_multicoin_tx_sign(WALLEVE_COINS_BTC, wl_vch_string(tx_signed01), sp01, tx_signed02);
    printf("[2] sign:%s\n", wl_vch_string(tx_signed02));

    vch_t *ret_json02 = wl_vch_new();
    wl_multicoin_tx_verify(WALLEVE_COINS_BTC, wl_vch_string(tx_signed02), sp01, ret_json02);
    printf("[3] verify:%s", wl_vch_string(ret_json02));
    printf("/*----------交易2：结束*/\n");

    // char multisig1[1024] = {'\0'};
    // vch_t *script_addr = wl_vch_new();
    // vch_t *script_export = wl_vch_new();
    // sprintf(multisig1, "{\"type\":\"multisig\", \"param\":{\"req\":%d, \"pubkeys\":[\"%s\", \"%s\", \"%s\"]}}", 2, wl_vch_string(pubkey1), wl_vch_string(pubkey2), wl_vch_string(pubkey3));
    // wl_multicoin_script_addnew(WALLEVE_COINS_BTC, multisig1, script_addr);
    wl_multicoin_script_export(WALLEVE_COINS_BTC, wl_vch_string(script_addr), script_export);
    printf("script addr:%s\n", wl_vch_string(script_addr));

    char *script_str[1024] = {'\0'};
    size_t script_str_size = 211;
    wl_uintx_tohex(script_export->ptr, wl_vch_len(script_export), script_str, script_str_size);
    char *redeem_script = "5221027f35b748e588b281bacada05d30a4ae9738ef1e5d5b8eaccba8a2cf7ae8db215210207eb3297e0ce22fbf0b441fd509ba1c7971a5de2f19ba8035075888940642a292102ab6b5f58b5460a181c88c62bdd1f2245e706d2414afa63786d1a8f4f373f685353ae";
    printf("cmp:%d, script: %s\n", strcmp(redeem_script, script_str), script_str);
    // vch_t *rs = wl_vch_new_hex(redeem_script);
    // printf("script len:%d, cmp:%d\n", wl_vch_len(rs), wl_vch_cmp(script_export, rs));

    printf("------------------------------BTC END-----------------------\n\n");
    
    return 0;
}

int btc_test()
{
    printf("==================== BTC BEGIN========================\n\n");
    
    /* */
    printf("create key test:\n");
    if (createkey(WALLEVE_COINS_BTC) < 0)
    {
        return -1;
    }
    printf("import key test:\n");
    if (importkey(WALLEVE_COINS_BTC,privkey,address) < 0)
    {
        return -1;
    }
    printf("create script test:\n");
    if (createscript(WALLEVE_COINS_BTC,multisig,multisig_addr) < 0)
    {
        return -1;
    }
    // if (createscript(WALLEVE_COINS_BTC,coldminting,coldminting_addr) < 0)
    // {
    //     return -1;
    // }
    // if (createscript(WALLEVE_COINS_BTC,multisigcoldminting,multisigcoldminting_addr) < 0)
    // {
    //     return -1;
    // }
    
    printf("parse tx test:\n");
    if (parsetx(WALLEVE_COINS_BTC,tx1,in1) < 0)
    {
        return -1;
    }
    // if (parsetx(WALLEVE_COINS_BTC,tx5,in5) < 0)
    // {
    //     return -1;
    // }
    printf("sign tx test:\n");

    if (signtx(WALLEVE_COINS_BTC,tx1,in1) < 0)
    {
        return -1;
    }
    printf("\n");
    // if (signtx(WALLEVE_COINS_LMC,tx3,in3) < 0)
    // {
    //     return -1;
    // }

    printf("verify tx test:\n");
    if (verifytx(WALLEVE_COINS_BTC,tx1_sign,in1) < 0)
    {
        return -1;
    }
    printf("\n");
    // if (verifytx(WALLEVE_COINS_LMC,tx4,in4) < 0)
    // {
    //     return -1;
    // }

    // printf("\n");
    // if (verifytx(WALLEVE_COINS_LMC,tx5,in5) < 0)
    // {
    //     return -1;
    // }

    // printf("\n");
    // if (verifytx(WALLEVE_COINS_LMC,tx6,in6) < 0)
    // {
    //     return -1;
    // }
    printf("==================== BTC END========================\n\n");
    return 0; 
}
