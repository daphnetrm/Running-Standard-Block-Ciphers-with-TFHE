#ifndef H_ANNEXE
#define H_ANNEXE

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <math.h>
#include <vector>
#include <iostream>
#include <cassert>
#include <ctime>

#include "base_b_keyswitchkey.h"
#include "base_b_keyswitch.h"
#include "tables.h"
#include "bootstrapping.h"

using namespace std; 

//void my_testv(TorusPolynomial *testv, int32_t N, uint8_t B, uint8_t idx, uint8_t digit, word8 tab[256]);

//void my_testv_mvb(IntPolynomial *testv, int32_t N, uint8_t B, uint8_t idx, word8 tab[256]);

void print_coef_b16(TorusPolynomial *testv); 
void print_int_b16(IntPolynomial *testv);
void print_testv(TorusPolynomial *testv);
void ks_batching(int i, uint8_t B, vector <LweSample*> &resLwe, vector<TLweSample*> &resTLwe, const TLweKey * k_out , BaseBKeySwitchKey* ks_key);
void tLweMulByXai(TLweSample *result, int32_t ai, const TLweSample *bk, const TLweParams *params);
void verif_decr(LweSample *temp, const LweKey * k_in,  const LweParams *in_params, const LweBootstrappingKey *bk, uint32_t m_size);
void verif_init(LweSample *temp, const LweKey * k_in,  const LweParams *in_params, const LweBootstrappingKey *bk, uint32_t m_size);
void XOR_fhe(vector <LweSample*> &v1, vector <LweSample*> &v2, TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void Enc_tab(vector <LweSample*> tab_fhe[4][8] ,word8 tab[4][8], TFheGateBootstrappingSecretKeySet* key);


   
#endif
