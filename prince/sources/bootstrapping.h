#ifndef H_BOOTSTRAPPING
#define H_BOOTSTRAPPING

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <math.h>
#include <vector>
#include <iostream>
#include <cassert>
#include <ctime>
#include <tfhe/tfhe_garbage_collector.h>


#include "base_b_keyswitchkey.h"
#include "base_b_keyswitch.h"
#include "tlwe-functions-extra.h"
#include "tlwekeyswitch.h"
#include "tables.h"
#include "annexe.h"
#include "prince_ref.h"


using namespace std; 



void boot_lut(TLweSample *result,
	      TLweSample * lut,
	      const LweBootstrappingKey *bk,
	      int32_t *bara,
	      int32_t barb );

void boot_lut_FFT(TLweSample *result,
	      TLweSample * lut,
	      const LweBootstrappingKeyFFT *bk,
	      int32_t *bara,
	      int32_t barb );

void deref_mvb(vector <LweSample*> &result,
	       TFheGateBootstrappingSecretKeySet* gk,
	       vector <LweSample*> &tab_ciphers,
	       uint32_t m_size,
	       uint8_t d, 
	       uint8_t B,
	       BaseBKeySwitchKey* ks_key,
	       word8 tab_d0[256],
	       word8 tab_d1[256]);
void deref_boot(vector <LweSample*> &result,
		TFheGateBootstrappingSecretKeySet* gk,
		vector <LweSample*> &tab_ciphers,
		BaseBKeySwitchKey* ks_key,
		word8 tab_d0[256],
		word8 tab_d1[256]);
void deref_mvb_small_table(vector <LweSample*> &result,
	       TFheGateBootstrappingSecretKeySet* gk,
	       vector <LweSample*> &tab_ciphers,
	       uint32_t m_size,
	       uint8_t d, 
	       uint8_t B,
	       BaseBKeySwitchKey* ks_key,
	       word8 tab[16]);
void deref_boot_small_table(vector <LweSample*> &result,
		TFheGateBootstrappingSecretKeySet* gk,
		vector <LweSample*> &tab_ciphers,
		BaseBKeySwitchKey* ks_key,
		word8 tab[16]);

void deref_single_boot(vector <LweSample*> &result,
		       TFheGateBootstrappingSecretKeySet* gk,
		       vector <LweSample*> &tab_ciphers,
		       BaseBKeySwitchKey* ks_key,
		       word8 idx,
		       word8 tab[16]);

void test_deref(int m_size, int base);

#endif
