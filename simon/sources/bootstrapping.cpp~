#include "bootstrapping.h"


using namespace std; 


float norme_max = 0.0;



void boot_lut(TLweSample* result,
	      TLweSample* lut,
	      const LweBootstrappingKey* bk,
	      int32_t* bara,
	      int32_t barb) {
  const TGswParams* bk_params = bk->bk_params;
  const TLweParams* accum_params = bk->accum_params;
  const LweParams* in_params = bk->in_out_params;
  const int32_t N = accum_params->N;
  const int32_t Nx2 = 2 * N;
  const int32_t n = in_params->n;
  if (barb != 0) {
    tLweMulByXai(result, Nx2-barb, lut, accum_params);
  }
  else {
    tLweCopy(result, lut, accum_params);
  }
  tfhe_blindRotate(result, bk->bk, bara, n, bk_params);
}




void boot_lut_FFT(TLweSample* result,
	      TLweSample* lut,
	      const LweBootstrappingKeyFFT* bkFFT,
	      int32_t* bara,
	      int32_t barb) {
  const TGswParams* bk_params = bkFFT->bk_params;
  const TLweParams* accum_params = bkFFT->accum_params;
  const LweParams* in_params = bkFFT->in_out_params;
  const int32_t N = accum_params->N;
  const int32_t Nx2 = 2 * N;
  const int32_t n = in_params->n;
  if (barb!=0) {
    tLweMulByXai(result, Nx2-barb, lut, accum_params);
  }
  else {
    tLweCopy(result, lut, accum_params);
  }
  tfhe_blindRotate_FFT(result, bkFFT->bkFFT, bara, n, bk_params);
}




void deref_mvb(vector <LweSample*> &result,
	       TFheGateBootstrappingSecretKeySet* gk,
	       vector <LweSample*> &tab_ciphers,
	       uint32_t m_size,
	       uint8_t d, 
	       uint8_t B,
	       BaseBKeySwitchKey* ks_key,
	       word8 tab_d0[256],
	       word8 tab_d1[256]) {
  const LweBootstrappingKeyFFT* bkFFT = gk->cloud.bkFFT;
  const TGswParams* bk_params = bkFFT->bk_params;
  const TLweParams* accum_params = bkFFT->accum_params;
  const LweParams* in_params = gk->lwe_key->params;

  const int32_t N = accum_params->N;
  const int32_t Nx2 = 2 * N;
  const int32_t n = in_params->n;

  const LweKey* k_in = gk->lwe_key;
  const TLweKey* k_out = &gk->tgsw_key->tlwe_key;

  int count = 1;
  uint32_t power = pow(B, d-count);
    
  Torus32 m_sizex2 = dtot32(1./(2*m_size));
  int32_t barb = 0;
  uint8_t nb_digits = result.size();
  int k;
  
  // On répète autant de fois que nécessaire pour avoir tous les digits
  for (k = 0; k < nb_digits; ++k) {
    vector<LweSample*> resLwe(B);
    vector<TLweSample*> resTLwe(power/B); 
    LweSample* temp = new_LweSample(&bkFFT->accum_params->extracted_lweparams);
    TLweSample* rTLwe = new_TLweSample(k_out->params);
    
    TorusPolynomial* testv0 = new_TorusPolynomial(N);
    IntPolynomial* poli = new_IntPolynomial(N);
    count = 1;
    power = pow(B, d-count);
    int var = 0;
    int32_t* bara = new int32_t[N];
    barb = modSwitchFromTorus32((tab_ciphers[1]->b+m_sizex2), Nx2); 
    for (int32_t i = 0; i < n; i++) {
      bara[i] = modSwitchFromTorus32(tab_ciphers[1]->a[i], Nx2);
    }
    // on créer le polynôme v0 de l'algo de mvb
    test_v0(testv0,N);

    // puis, on créer (0,testv0) = acc
    TLweSample* acc = new_TLweSample(bk_params->tlwe_params);
    TorusPolynomial* testvectbis = new_TorusPolynomial(N);
    if (barb != 0)
      torusPolynomialMulByXai(testvectbis, 2*N - barb, testv0); 
    else
      torusPolynomialCopy(testvectbis, testv0);
    tLweNoiselessTrivial(acc, testvectbis, bk_params->tlwe_params);

    // on applique le blind rotate sur acc)
    tfhe_blindRotate_FFT(acc, bkFFT->bkFFT, bara, n, bk_params);

    // on conserve les valeurs obtenues pour les itérations 
    TorusPolynomial* v0 = new_TorusPolynomial(N);
    TorusPolynomial* va = new_TorusPolynomial(N);
    torusPolynomialCopy(v0, acc->b);
    torusPolynomialCopy(va, acc->a);

    // on créer des polynômes qui serviront à recueillir les résultats du produit ACC*poli
    TorusPolynomial* tmpb = new_TorusPolynomial(N);
    TorusPolynomial* tmpa = new_TorusPolynomial(N);

    //ici aussi parallélisation possible ? attention pointeurs
    for(int i = 0; i < power; ++i) {
      if(k==0)
	testv_vi_b16(poli, N, i, tab_d0);
      else
	testv_vi_b16(poli, N, i, tab_d1);
      // on effectue ACCi = ACC*poli
      torusPolynomialMultFFT(tmpb, poli,v0);
      torusPolynomialMultFFT(tmpa, poli,va);
      // on récupère les bonnes valeurs
      torusPolynomialCopy(acc->b, tmpb);
      torusPolynomialCopy(acc->a, tmpa);
      // on extrait
      tLweExtractLweSample(temp,acc,&bk_params->tlwe_params->extracted_lweparams,bk_params->tlwe_params);
      
      resLwe[i%B] = new_LweSample(in_params);
      lweKeySwitch(resLwe[i%B], bkFFT->ks, temp);
    
      if (i%B == (B-1)) {
	ks_batching(i, B, resLwe, resTLwe, k_out, ks_key);
	var = 0;
      } else
	var +=1;  
    }
    // Le TLweSample contient les 16 dernières valeurs qui nous intéressent
    barb = modSwitchFromTorus32((tab_ciphers[0]->b+m_sizex2), Nx2); 
    for (int32_t i = 0; i < n; i++) {
      bara[i] = modSwitchFromTorus32(tab_ciphers[0]->a[i], Nx2);
    }

    boot_lut_FFT(rTLwe, resTLwe[0], bkFFT, bara, barb);
    tLweExtractLweSample(result[k], rTLwe, &bkFFT->accum_params->extracted_lweparams, accum_params);

    delete_TorusPolynomial(v0);
    delete_TorusPolynomial(va);
    delete_LweSample(temp);
    delete_TLweSample(rTLwe);
    resLwe.clear();
    resTLwe.clear();
    delete[] bara;
    delete_TorusPolynomial(testv0);
    delete_IntPolynomial(poli);
    delete_TorusPolynomial(testvectbis);
    delete_TorusPolynomial(tmpa);
    delete_TorusPolynomial(tmpb);
    delete_TLweSample(acc);
  }
}



void deref_boot(vector <LweSample*> &result,
		TFheGateBootstrappingSecretKeySet* gk,
		vector <LweSample*> &tab_ciphers,
		BaseBKeySwitchKey* ks_key,
		word8 tab_d0[256],
		word8 tab_d1[256]) {
  const LweBootstrappingKey* bk = gk->cloud.bk;
  vector <LweSample*> u(result.size());
  for (int i = 0; i < result.size(); ++i)
    u[i] = new_LweSample(&bk->accum_params->extracted_lweparams);

  deref_mvb(u, gk, tab_ciphers, 32, 2, 16, ks_key, tab_d0, tab_d1);
  for(int i = 0; i< result.size(); ++i){
    lweKeySwitch(result[i], bk->ks, u[i]);
  }
  for(int i = 0; i< result.size(); ++i)
    delete_LweSample(u[i]);
}





void deref_single_boot(vector <LweSample*> &result,
		       TFheGateBootstrappingSecretKeySet* gk,
		       vector <LweSample*> &x,
		       BaseBKeySwitchKey* ks_key,
		       word8 idx,
		       word8 tab[16]){
  const LweBootstrappingKeyFFT* bkFFT = gk->cloud.bkFFT;
  const TGswParams* bk_params = bkFFT->bk_params;
  const TLweParams* accum_params = bkFFT->accum_params;
  const LweParams* in_params = gk->lwe_key->params;
  const int32_t N = accum_params->N;
  const int32_t Nx2 = 2 * N;
  const int32_t n = in_params->n;
  LweSample *u = new_LweSample(&bkFFT->accum_params->extracted_lweparams);
  TorusPolynomial *testvect = new_TorusPolynomial(N);
  int32_t *bara = new int32_t[N];
  int m_size=32;
  Torus32 m_sizex2 = dtot32(1./(2*m_size));
  int32_t barb = modSwitchFromTorus32((x[idx]->b+m_sizex2), Nx2);
  for (int32_t i = 0; i < n; i++) {
    bara[i] = modSwitchFromTorus32(x[idx]->a[i], Nx2);
  }

  //the initial testvec
  testv_and(testvect, N, tab);
  tfhe_blindRotateAndExtract_FFT(u, testvect,  bkFFT->bkFFT, barb, bara, n, bk_params);
  delete[] bara;
  delete_TorusPolynomial(testvect);

  // Key Switching
  lweKeySwitch(result[idx], bkFFT->ks, u);
  delete_LweSample(u);
}
