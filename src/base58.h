// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_BASE58_H 
#define  WALLEVE_BASE58_H
#include <stdlib.h>
#include <stdint.h>

int wl_base58_encode(const void *data,size_t data_len,char *b58,size_t b58_len);
int wl_base58_decode(const char *b58,void *data,size_t *data_len);
int wl_base58_checkencode(const void *data,size_t data_len,char *b58,size_t b58_len);
int wl_base58_checkdecode(const char *b58,void *data,size_t *data_len);

#endif //WALLEVE_BASE58_H
