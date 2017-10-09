// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_MULTICOIN_H
#define  WALLEVE_MULTICOIN_H

#include <stdlib.h>
#include <stdint.h>

#include "coins.h"
#include "vch.h"

/* Global init & deinit */

// Initialize multicoin library 
int wl_multicoin_init(void);

// Release resource for multicoin library
void wl_multicoin_deinit(void);

/* Key */

// Create new key & return relvant address
int wl_multicoin_key_create(coin_t coin,vch_t *addr);

// Import private key & return relvant address
int wl_multicoin_key_import(coin_t coin,const char *privkey,vch_t *addr);

// Remove key corresponding to address 
void wl_multicoin_key_remvoe(coin_t coin,const char *addr);

// Reveal private key corresponding to address
int wl_multicoin_key_privkey(coin_t coin,const char *addr,vch_t *privkey);

// Reveal public key corresponding to address
int wl_multicoin_key_pubkey(coin_t coin,const char *addr,vch_t *pubkey);

/* Script/Contract */

// Add script dependent on context,return relvant address
// LMC/BTC:
// 
int wl_multicoin_script_addnew(coin_t coin,const char *context,vch_t *addr);

// Remove script corresponding to address 
void wl_multicoin_script_remove(coin_t coin,const char *addr);

// Export script corresponding to address
int wl_multicoin_script_export(coin_t coin,const char *addr,vch_t *script);

/* Transaction */

// Parse transaction & return elems in json object
// LMC/BTC:
//   tx_data : serialized tx data
//   tx_ctxt : json array of scriptpubkey for each txin 
//           : ["script_pubkey_vin[0]","script_pubkey_vin[1]",...]
//   tx_json : tx in json
int wl_multicoin_tx_parse(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_json);

// Sign transaction, return transaction data with signature
// LMC/BTC:
//   tx_data : serialized tx data
//   tx_ctxt : json array of scriptpubkey for each txin 
//           : ["script_pubkey_vin[0]","script_pubkey_vin[1]",...]
//   tx_signed : serialized tx data with signature (if have key)
int wl_multicoin_tx_sign(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *tx_signed);

// Verify each signature for transacion input, return verification in json
// LMC/BTC:
//   tx_data : serialized tx data
//   tx_ctxt : json array of scriptpubkey for each txin 
//           : ["script_pubkey_vin[0]","script_pubkey_vin[1]",...]
//   ret_json : result in json
int wl_multicoin_tx_verify(coin_t coin,const char *tx_data,const char *tx_ctxt,vch_t *ret_json);

#endif //WALLEVE_MULTICOIN_H

