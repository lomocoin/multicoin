CC  = gcc
AR  = ar
CFLAGS = -O2 -g \
         -D__USE_GNU -D__USE_XOPEN -D__USE_XOPEN2K  -Iinclude -Isrc/secp256k1/include -Isrc/secp256k1 -I.\
         -Wno-missing-prototypes -Wno-trigraphs -Werror=return-type		\
         -Wno-missing-braces 	\
         -Wparentheses -Wswitch -Wno-unused-function -Wunused-label		\
         -Wno-unused-parameter -Wunused-variable -Wunused-value -Wempty-body	\
         -Wno-unknown-pragmas -pedantic -Wshadow	\
         -Wno-conversion 		\
         -Wint-conversion 	\
         -Wpointer-sign -Wno-format-extra-args 			\
         -Wdeprecated-declarations -Wno-sign-conversion
LDFLAGS = -lrt -lm -lpthread 
TARGET = libmulticoin.la
TESTTARGET = mctest
OBJ = 	\
      src/rmd160.o	\
      src/base58.o	\
      src/sha3.o	\
      src/crypto.o	\
      src/vch.o		\
      src/buff.o	\
      src/json.o	\
      src/coins.o	\
      src/key.o		\
      src/script.o	\
      src/tx.o		\
      src/sato.o	\
      src/lmc.o		\
      src/btc.o		\
      src/eth.o		\
      src/multicoin.o	
TESTOBJ = $(OBJ) src/test.o src/bench_lmc.o src/bench_eth.o
TESTNET:= 0
CFLAGS += -DTESTNET=$(TESTNET)

all:$(TARGET)


$(TARGET):$(OBJ)
	$(AR) -rs $@ $^	

test:$(TESTOBJ)
	$(CC) -o $(TESTTARGET) $(TESTOBJ) $(LDFLAGS)
%.o:%.c
	$(CC) -c $(CFLAGS) -o $@ $< 

clean:
	-rm -f $(OBJ)
	-rm -f $(TARGET)
	-rm -f $(TESTTARGET)

