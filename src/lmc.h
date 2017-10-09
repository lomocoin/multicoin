// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
    
#ifndef  WALLEVE_LMC_H
#define  WALLEVE_LMC_H
    
#include <stdlib.h>
#include <stdint.h>
#include "coins.h"

int wl_lmc_is_compressed();
int wl_lmc_get_addr(const uint8_t *pubkey,char *addr,size_t len);
int wl_lmc_get_priv(const uint8_t *secret,vch_t *privkey);
int wl_lmc_set_priv(const char *privkey,uint8_t *secret);
int wl_lmc_build_script(const char *context,vch_t *script,vch_t *scriptid);
int wl_lmc_parse_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_json);
int wl_lmc_sign_tx(const char *tx_data,const char *tx_ctxt,vch_t *tx_signed);
int wl_lmc_verify_tx(const char *tx_data,const char *tx_ctxt,vch_t *ret_json);

#endif //WALLEVE_LMC_H

