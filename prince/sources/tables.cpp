#include "tables.h"
#include "bootstrapping.h"



/* RC is the table of the Round Constants.
 */
  uint64_t RC[12] = {
    0x0000000000000000,
    0x13198a2e03707344,
    0xa4093822299f31d0,
    0x082efa98ec4e6c89,
    0x452821e638d01377,
    0xbe5466cf34e90c6c,
    0x7ef84f78fd955cb1,
    0x85840851f1ac43aa,
    0xc882d32f25323c54,
    0x64a51195e0e3610d,
    0xd3b5a399ca0c2399,
    0xc0ac29b7c97c50dd};



word8 sbox[16] = {
    0xb, 0xf, 0x3, 0x2,
    0xa, 0xc, 0x9, 0x1,
    0x6, 0x7, 0x8, 0x0,
    0xe, 0x5, 0xd, 0x4
  };


word8 sbox_inv[16] = {
    0xb, 0x7, 0x3, 0x2,
    0xf, 0xd, 0x8, 0x9,
    0xa, 0x6, 0x4, 0x0,
    0x5, 0xe, 0xc, 0x1
  };

word8 id[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};


word8 XOR_b16[256] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};



word8 and_8[16]={0,0,0,0,0,0,0,0,8,8,8,8,8,8,8,8};

word8 and_4[16]={0,0,0,0,4,4,4,4,0,0,0,0,4,4,4,4};

word8 and_2[16]={0,0,2,2,0,0,2,2,0,0,2,2,0,0,2,2};

word8 and_1[16]={0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1};









// xor digit à digit v1 et v2
// renvoie le résultat dans v1
void XOR_fhe(vector <LweSample*> &v1,
	     vector <LweSample*> &v2,
	     TFheGateBootstrappingSecretKeySet* gk,
	     BaseBKeySwitchKey* ks_key) {
  vector <LweSample*> d0;
  vector <LweSample*> d1;
  vector <LweSample*> res0 (1);
  vector <LweSample*> res1 (1);
  d0.push_back(v1[0]);
  d0.push_back(v2[0]);
  d1.push_back(v1[1]);
  d1.push_back(v2[1]);
  res0[0] = new_LweSample(gk->lwe_key->params);
  deref_boot(res0, gk, d0, ks_key, XOR_b16, XOR_b16);
  res1[0] = new_LweSample(gk->lwe_key->params);
  deref_boot(res1, gk, d1, ks_key, XOR_b16, XOR_b16);
  res0.push_back(res1[0]);
  v1.swap(res0);
  d0.clear();
  d1.clear();
  res0.clear();
  res1.clear();
}




//applique le AND bit à bit et renvoie le résultat dans result
void and_fhe (vector <LweSample*> &result,
	      vector <LweSample*> &b,
	      TFheGateBootstrappingSecretKeySet* gk,
	      BaseBKeySwitchKey* ks_key,
	      word8 tab[16]
	      ) {
  deref_single_boot(result, gk, b, ks_key, 0, tab);
}



void xor_key_fhe(vector <LweSample*> result[8],
	      vector <LweSample*> b[8],
	      TFheGateBootstrappingSecretKeySet* gk,
	      BaseBKeySwitchKey* ks_key
	      ) {
  for(int i=0; i<8; i++)
    XOR_fhe(result[i], b[i], gk, ks_key);
}


void testv_and(TorusPolynomial *testv, int32_t N, word8 tab[16]){
  uint32_t steps = N/16;
  for(int k = 0 ; k < 16 ; ++k) {
    for(int j = 0; j < steps; ++j) {
      testv->coefsT[steps*k + j] = dtot32((double)tab[k]/32);
    }   
  }
}


// remplacer pour la base 16 specifiquement 
void test_v0(TorusPolynomial *testv, int32_t N){
    for(int j = 0; j < N; ++j) 
      testv->coefsT[j] = dtot32(0.015625); // 1/64
}


void testv_vi_b16(IntPolynomial *testv, int32_t N, uint8_t idx, word8 tab[256]) {
  uint32_t steps = N/16;
  for(int k = 0 ; k < 16 ; ++k) {
    for(int j = 0; j < steps; ++j) {
      if(steps*k + j == 0)
	testv->coefs[0]= tab[16*idx]+tab[16*idx+15];
      else if((steps*k + j)%(steps)!=0)
	testv->coefs[steps*k + j]=0;
      else
	testv->coefs[steps*k + j] = (tab[16*idx + k]-tab[16*idx + k-1]);
    }
  } 
}



void tLweMulByXai(TLweSample *result,
		  int32_t ai,
		  const TLweSample *bk,
		  const TLweParams *params) {
    const int32_t k = params->k;
    for (int32_t i = 0; i <= k; i++)
        torusPolynomialMulByXai(&result->a[i], ai, &bk->a[i]);
}

void ks_batching(int i,
		 uint8_t B,
		 vector <LweSample*> &resLwe,
		 vector<TLweSample*> &resTLwe,
		 const TLweKey * k_out ,
		 BaseBKeySwitchKey* ks_key) {
      resTLwe[i/B] = new_TLweSample(k_out->params);
      BaseBExtra::KeySwitch_Id(resTLwe[i/B], ks_key, resLwe);
      for(int m = 0; m<B; ++m)
	delete_LweSample(resLwe[m]);
}



void Enc_tab (vector <LweSample*> tab_fhe[8],
	      word8 tab[8],
	      TFheGateBootstrappingSecretKeySet* key) {
  double alpha = key->lwe_key->params->alpha_min;
  for(int j = 0; j<8; ++j){
    tab_fhe[j].push_back(new_LweSample(key->lwe_key->params));
    lweSymEncrypt(tab_fhe[j][0], modSwitchToTorus32(tab[j]/16, 32), alpha, key->lwe_key);
    tab_fhe[j].push_back(new_LweSample(key->lwe_key->params));
    lweSymEncrypt(tab_fhe[j][1], modSwitchToTorus32(tab[j]%16, 32), alpha, key->lwe_key);
  }
}


void encode(word8 retour[8], uint64_t m){
  for(int j = 7; j>=0 ; j--)
    retour[7-j] = (m>>(8*j));
}



/*

void print_tables_Tx_b16(){
 printf("word8 XOR_b16 = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",XOR_b16[i]);
  }
  printf("%d};\n\n",(XOR_b16[255]));
  
  printf("word8 XOR_0_b16[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",XOR_b16[i]%16);
  }
  printf("%d};\n\n",(XOR_b16[255]%16));
  printf("word8 XOR_1_b16[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",(XOR_b16[i]/16));
  }
  printf("%d};\n\n",(XOR_b16[255]/16));
}


void print_tables_XOR(){
  printf("word8 XOR_b16[256] = {");
  for(int i = 0; i <16; ++i){
    for(int j = 0; j<16; ++j){
      printf("%d, ", i^j);
    }
  }
  printf("};\n\n");
}*/

