#ifndef __CLEFIA_H__
#define __CLEFIA_REF_H__

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
typedef unsigned int word32;
typedef unsigned char word8;



void xor_rk_fhe(vector <LweSample*> a[4],vector <LweSample*> rc_k[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void core_f0_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void mul_m0_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void core_f1_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void mul_m1_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void f0_fhe(vector <LweSample*> a[4], vector <LweSample*> rc_k[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);
void f1_fhe(vector <LweSample*> a[4], vector <LweSample*> rc_k[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void encryption_fhe(vector <LweSample*> a[4][4], vector <LweSample*> wk[4][4],  vector <LweSample*> rc_k[36][4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

#endif //__CLEFIA_H__
