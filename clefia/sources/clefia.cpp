#include <stdio.h>
#include <stdlib.h>
#include "clefia.h"
#include "tables.h"
#include "bootstrapping.h"



int f4(int i){// returns i+2 mod(4)
  if(i==0)
    return 2;
  else if(i==1)
    return 3;
  else if(i==2)
    return 0;
  else
    return 1;
}


int f2(int i){
  if(i==0)
    return 1;
  else if(i==1)
    return 0;
  else if(i==2)
    return 3;
  else
    return 2;
}


void xor_rk_fhe(vector <LweSample*> a[4],vector <LweSample*> rc_k[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
  for(int i = 0; i<4; i++)
    XOR_fhe(a[i], rc_k[i], gk, ks_key);
}

void core_f0_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
   deref_boot(a[0], gk, a[0], ks_key, s0_0, s0_1);
   deref_boot(a[1], gk, a[1], ks_key, s1_0, s1_1);
   deref_boot(a[2], gk, a[2], ks_key, s0_0, s0_1);
   deref_boot(a[3], gk, a[3], ks_key, s1_0, s1_1);  
}

void core_f1_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
   deref_boot(a[0], gk, a[0], ks_key, s1_0, s1_1);
   deref_boot(a[1], gk, a[1], ks_key, s0_0, s0_1);
   deref_boot(a[2], gk, a[2], ks_key, s1_0, s1_1);
   deref_boot(a[3], gk, a[3], ks_key, s0_0, s0_1);  
}

void mul_m0_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
  /*
    a[0]= 1*a[0] + 2*a[1] + 4*a[2] + 6*a[3]
    a[1]= 2*a[0] + 1*a[1] + 6*a[2] + 4*a[3]
    a[2]= 4*a[0] + 6*a[1] + 1*a[2] + 2*a[3]
    a[3]= 6*a[0] + 4*a[1] + 2*a[2] + 1*a[3]
*/
  vector <LweSample*> b[4];
  for(int i = 0; i<4 ; ++i){
    b[i].push_back(new_LweSample(gk->lwe_key->params));
    b[i].push_back(new_LweSample(gk->lwe_key->params));
  }
  int k;
  vector <LweSample*> tmp(2);
    tmp[0] = new_LweSample(gk->lwe_key->params);
    tmp[1] = new_LweSample(gk->lwe_key->params);

  for(k =0; k<4; k++){  
    mul2_fhe(b[k], a[f2(k)],gk, ks_key);
    mul4_fhe(tmp, a[f4(k)], gk, ks_key);
    XOR_fhe(b[k], tmp, gk, ks_key);  
    mul6_fhe(tmp, a[3-k], gk, ks_key);
    XOR_fhe(b[k], tmp, gk, ks_key);
    XOR_fhe(b[k], a[k], gk, ks_key);   
    
  }
  tmp.clear();
  for(int i = 0; i < 4; i++)
      a[i].swap(b[i]); 
}

void mul_m1_fhe(vector <LweSample*> a[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
 /*
    a[0]= 1*a[0] + 8*a[1] + 2*a[2] + a*a[3]
    a[1]= 8*a[0] + 1*a[1] + a*a[2] + 2*a[3]
    a[2]= 2*a[0] + a*a[1] + 1*a[2] + 8*a[3]
    a[3]= a*a[0] + 2*a[1] + 8*a[2] + 1*a[3]
*/
  vector <LweSample*> b[4];
  for(int i = 0; i<4 ; ++i){
    b[i].push_back(new_LweSample(gk->lwe_key->params));
    b[i].push_back(new_LweSample(gk->lwe_key->params));
  }
  int k;
  vector <LweSample*> tmp(2);
  tmp[0] = new_LweSample(gk->lwe_key->params);
  tmp[1] = new_LweSample(gk->lwe_key->params);
  for(k =0; k<4; ++k){
    mul8_fhe(b[k], a[f2(k)],gk, ks_key);
    mul2_fhe(tmp, a[f4(k)], gk, ks_key);
    XOR_fhe(b[k], tmp, gk, ks_key);  
    mula_fhe(tmp, a[3-k], gk, ks_key);
    XOR_fhe(b[k], tmp, gk, ks_key);
    XOR_fhe(b[k], a[k], gk, ks_key);
   
  }
   tmp.clear();
  for(int i = 0; i < 4; i++)
      a[i].swap(b[i]); 
}

void f0_fhe(vector <LweSample*> a[4], vector <LweSample*> rc_k[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
  xor_rk_fhe(a, rc_k, gk, ks_key);
  core_f0_fhe(a, gk, ks_key);
  mul_m0_fhe(a, gk, ks_key);
}

void f1_fhe(vector <LweSample*> a[4], vector <LweSample*> rc_k[4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key){
  xor_rk_fhe(a, rc_k, gk, ks_key);
  core_f1_fhe(a, gk, ks_key);
  mul_m1_fhe(a, gk, ks_key);
}


void swap_fhe(vector <LweSample*> a[4][4]){
  for(int i=0; i<4; i++){
   a[3][i].swap(a[0][i]);
   a[0][i].swap(a[1][i]);
   a[1][i].swap(a[2][i]);
  }
   
}

void encryption_fhe(vector <LweSample*> a[4][4], vector <LweSample*> wk[4][4],  vector <LweSample*> rc_k[36][4], TFheGateBootstrappingSecretKeySet* gk, BaseBKeySwitchKey* ks_key) {
  vector <LweSample*> tmp[4];
  for(int i=0; i<4; i++){
    tmp[i].push_back(new_LweSample(gk->lwe_key->params));
    tmp[i].push_back(new_LweSample(gk->lwe_key->params));
  }
  //(0) On xore les white keys
  xor_rk_fhe(a[1], wk[0], gk, ks_key);
  xor_rk_fhe(a[3], wk[1], gk, ks_key);
  
  //(1) On applique les 18 rounds
  for(int i=0; i<18; i++){
    printf("round %d\n", i);
    for(int j =0; j<4; j++){
      lweCopy(tmp[j][0], a[0][j][0], gk->lwe_key->params);
      lweCopy(tmp[j][1], a[0][j][1], gk->lwe_key->params);
    }
    f0_fhe(tmp, rc_k[2*i], gk, ks_key);
    xor_rk_fhe(a[1], tmp, gk, ks_key);

    for(int j =0; j<4; j++){
      lweCopy(tmp[j][0], a[2][j][0], gk->lwe_key->params);
      lweCopy(tmp[j][1], a[2][j][1], gk->lwe_key->params);
    }
    f1_fhe(tmp, rc_k[2*i+1], gk, ks_key);
    xor_rk_fhe(a[3], tmp, gk, ks_key);

    if(i!=17)
      swap_fhe(a);
  }
  //(2) On xore les white keys
  xor_rk_fhe(a[1], wk[2], gk, ks_key);
  xor_rk_fhe(a[3], wk[3], gk, ks_key);
}
