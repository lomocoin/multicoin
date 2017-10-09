// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx.h"

int wl_tx_parse(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_json)
{
    struct wl_coin_operation *op = wl_get_coin_operation(coin);
    return op->parse_tx(tx_data,tx_ctxt,tx_json);
}

int wl_tx_sign(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_signed)
{
    struct wl_coin_operation *op = wl_get_coin_operation(coin);
    return op->sign_tx(tx_data,tx_ctxt,tx_signed);
}

int wl_tx_verify(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *ret_json)
{
    struct wl_coin_operation *op = wl_get_coin_operation(coin);
    return op->verify_tx(tx_data,tx_ctxt,ret_json);
}
