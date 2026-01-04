#ifndef H_TABLES
#define H_TABLES

#include <stdio.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include "base_b_keyswitchkey.h"
#include "base_b_keyswitch.h"

#define u64 uint64_t
typedef unsigned int word32;
typedef unsigned char word8;
using std::vector;


extern word8 and_8[16];
extern word8 and_c[16];
extern word8 shift_1[16];
extern word8 shift_2[16];

void XOR_fhe(vector <LweSample*> &v1, vector <LweSample*> &v2, TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void AND_fhe(vector <LweSample*> &v1, vector <LweSample*> &v2, TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);


void testv_and(TorusPolynomial *testv, int32_t N, word8 tab[16]);

void tLweMulByXai(TLweSample *result, int32_t ai, const TLweSample *bk, const TLweParams *params);
void ks_batching(int i, uint8_t B, vector <LweSample*> &resLwe, vector<TLweSample*> &resTLwe, const TLweKey * k_out, BaseBKeySwitchKey* ks_key);

void print_tables_Tx_b16();
void testv_b16(TorusPolynomial *testv, int32_t N, uint8_t idx, word8 tab[256]);
void testv_vi_b16(IntPolynomial *testv, int32_t N, uint8_t idx, word8 tab[256]);
void test_v0(TorusPolynomial *testv, int32_t N);


void Enc_tab (vector <LweSample*> tab_fhe[8], word8 tab[8], TFheGateBootstrappingSecretKeySet* key);
void encode(word8 retour[8], u64 m);





#endif
