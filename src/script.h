// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_SCRIPT_H
#define  WALLEVE_SCRIPT_H

#include <stdint.h>
#include "coins.h"
#include "vch.h"

void wl_script_init();
void wl_script_clear();

int  wl_script_addnew(coin_t coin,const char *context,vch_t *scriptid);
void wl_script_remove(coin_t coin,const char *scriptid);
int  wl_script_export(coin_t coin,const char *scriptid,vch_t *script);

#endif //WALLEVE_SCRIPT_H
