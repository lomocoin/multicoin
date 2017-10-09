// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_TX_H
#define  WALLEVE_TX_H

#include "coins.h"

int wl_tx_parse(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_json);
int wl_tx_sign(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_signed);
int wl_tx_verify(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *ret_json);

#endif //WALLEVE_TX_H
