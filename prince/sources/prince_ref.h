/*
Copyright 2016 Sebastien Riou
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*! \file prince_ref.h
    \brief Reference implementation of the Prince block cipher, complient to C99.
    'Reference' here means straightforward, unoptimized, and checked against the few test vectors provided in the original paper (http://eprint.iacr.org/2012/529.pdf).
    By defining the macro PRINCE_PRINT, one can print out all successive internal states.
*/

#ifndef __PRINCE_REF_H__
#define __PRINCE_REF_H__

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
typedef unsigned char word8;

uint64_t key_schedule(const uint64_t k0);

void xor_k_and_rc(vector <LweSample*> a[8],vector <LweSample*> rc_k[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void s_layer_fhe(vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void inv_s_layer_fhe(vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void m_prime_fhe(vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void shiftrows_fhe(vector <LweSample*> a[8], int d);

void m_layer_fhe(vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void inv_m_layer_fhe(vector <LweSample*> a[8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);

void prince_core_fhe(vector <LweSample*> a[8], vector <LweSample*> rc_k[12][8], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key);


#endif //__PRINCE_REF_H__
