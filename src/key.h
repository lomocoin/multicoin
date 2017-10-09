// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_KEY_H
#define  WALLEVE_KEY_H

#include "coins.h"
#include "vch.h"

void wl_key_init();
void wl_key_clear();

int  wl_key_create(coin_t coin,vch_t *addr);
int  wl_key_import(coin_t coin,const char *privkey,vch_t *addr);
void wl_key_remvoe(coin_t coin,const char *addr);
int  wl_key_privkey(coin_t coin,const char *addr,vch_t *privkey);
int  wl_key_pubkey(coin_t coin,const char *addr,vch_t *pubkey);
int  wl_key_pkdata(coin_t coin,const char *addr,vch_t *pkdata);
int  wl_key_sign(coin_t coin,const char *addr,const uint8_t *md32,vch_t *sig);

#endif //WALLEVE_KEY_H
