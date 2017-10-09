// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coins.h"

#include "lmc.h"
#include "btc.h"

static struct wl_coin_operation _op[WALLEVE_COINS_COUNT] = 
{
    {
        wl_lmc_is_compressed,
        wl_lmc_get_addr,
        wl_lmc_get_priv,
        wl_lmc_set_priv,
        wl_lmc_build_script,
        wl_lmc_parse_tx,
        wl_lmc_sign_tx,
        wl_lmc_verify_tx
    },
    {
        wl_btc_is_compressed,
        wl_btc_get_addr,
        wl_btc_get_priv,
        wl_btc_set_priv,
        wl_btc_build_script,
        wl_btc_parse_tx,
        wl_btc_sign_tx,
        wl_btc_verify_tx
    }
};

struct wl_coin_operation *wl_get_coin_operation(coin_t coin)
{
    return &_op[coin];
}

