#ifndef __SIMON_H__
#define __SIMON_REF_H__

#include <random>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <math.h>
#include <vector>
#include <iostream>
#include <cassert>
#include <unistd.h>
#include <time.h>
#include <tfhe/tfhe_garbage_collector.h>
#include "base_b_keyswitchkey.h"
#include "base_b_keyswitch.h"

using namespace std;
#define u64 uint64_t
typedef unsigned int word32;
typedef unsigned char word8;
using std::vector;

#define ROTL64(x,r) (((x)<<(r)) | (x>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r)) | ((x)<<(64-(r))))

void SimonKeySchedule(u64 K[],u64 rk[]);
void SimonEncrypt(u64 Pt[],u64 Ct[],u64 rk[]);
void SimonDecrypt(u64 Pt[],u64 Ct[],u64 rk[]);

void and_fhe (vector <LweSample*> &result, vector <LweSample*> &b, TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key, word8 tab[16]);
void and_64_fhe(vector <LweSample*> result[8], vector <LweSample*> b[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void xor_64_fhe(vector <LweSample*> result[8], vector <LweSample*> b[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void shift_8_fhe(vector <LweSample*> res[8], vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void shift_1_fhe(vector <LweSample*> res[8], vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void round_fhe(vector<LweSample*> x[8], vector<LweSample*> y[8], vector<LweSample*> a_shift_1[8], vector<LweSample*> a_shift_8[8], vector<LweSample*> rcki[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void encrypt_fhe(vector<LweSample*> x[8], vector<LweSample*> y[8], vector<LweSample*> rcki[68][8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);


#endif //__SIMON_H__
