#include "simon.h"
#include "tables.h"
#include "key_schedule.h"


int main(void){
  //(0) définir les paramètres pour le chiffrement homomorphe
  const int minimum_lambda = 110;
  static const int32_t N = 2048;
  static const int32_t k = 1;
  static const int32_t n = 1024;
  static const int32_t bk_l = 3;
  static const int32_t bk_Bgbit = 8;
  static const int32_t ks_basebit = 10;
  static const int32_t ks_length = 2;
  static const double ks_stdev = pow(5.6,-8);//standard deviation
  static const double bk_stdev = pow(9.6,-11);//standard deviation
  static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
  LweParams *params_in = new_LweParams(n, ks_stdev, max_stdev);
  TLweParams *params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
  TGswParams *params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

  TfheGarbageCollector::register_param(params_in);
  TfheGarbageCollector::register_param(params_accum);
  TfheGarbageCollector::register_param(params_bk);
  
  TFheGateBootstrappingParameterSet* params = new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
  uint32_t seed[] = {314, 1592, 657, 26363, 394, 4958, 4059, 3845};
  //mettre un bruit random
  tfhe_random_generator_setSeed(seed, 8);
  TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
  const LweKey * k_in = key->lwe_key;
  const TLweKey * k_out = &key->tgsw_key->tlwe_key;
  BaseBKeySwitchKey* ks_key = new_BaseBKeySwitchKey( key->lwe_key->params->n, 2, 10, 16, key->cloud.bk->accum_params);
  BaseBExtra::CreateKeySwitchKey(ks_key, k_in, k_out);
  printf("Etape 0 terminée\n");
  //(1) choisir le test vector
  u64 clef[2]= {0x0706050403020100, 0x0f0e0d0c0b0a0908};
  u64 rck[68];
  u64 plaintext[2]= {0x6373656420737265, 0x6c6c657661727420};
  u64 ciphertext[2]= {0x49681b1e1e54fe3f, 0x65aa832af84e0bbc};

  SimonKeySchedule(clef, rck);
  //(2) encodage sous forme de paquets de 8 octets = 64 bits
  word8 rcki_decompo[68][8];
  word8 msg[2][8];
  encode(msg[0], plaintext[0]);
  encode(msg[1], plaintext[1]);
  for(int i=0; i<68; i++)
    encode(rcki_decompo[i], rck[i]);

  //(3) chiffrer les clefs et le message en homomorphe
  vector<LweSample*> rcki_fhe[68][8];
  vector<LweSample*> x[8];
  vector<LweSample*> y[8];
  Enc_tab(x, msg[0], key);
  Enc_tab(y, msg[1], key);

  for(int i=0; i<68; i++)
    Enc_tab(rcki_fhe[i], rcki_decompo[i], key);

  printf("\nDébut chiffrement\n");
  //(4) appliquer l'algo de chiffrement dans le domaine homomorphe
   struct timespec begin, end; 
  clock_gettime(CLOCK_REALTIME, &begin);
  encrypt_fhe(x, y, rcki_fhe, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  long seconds = end.tv_sec - begin.tv_sec;
  long nanoseconds = end.tv_nsec - begin.tv_nsec;
  double elapsed = seconds + nanoseconds*1e-9;
  printf("Chiffrement symétrique terminé\n");
  //(5) déchiffrer et vérifier qu'il s'agit bien du bon chiffré symétrique.
  word8 base =16;
  for(int i=0; i<8; i++){
      int32_t decr0 = lweSymDecrypt(x[i][0], key->lwe_key, 32);
      double decrd0 = t32tod(decr0);
      int32_t decr1 = lweSymDecrypt(x[i][1], key->lwe_key, 32);
      double decrd1 = t32tod(decr1);
      msg[0][i]= (int)(decrd0*32+base)%base*base + (int)(decrd1*32+base)%base;
      decr0 = lweSymDecrypt(y[i][0], key->lwe_key, 32);
      decrd0 = t32tod(decr0);
      decr1 = lweSymDecrypt(y[i][1], key->lwe_key, 32);
      decrd1 = t32tod(decr1);
      msg[1][i]= (int)(decrd0*32+base)%base*base + (int)(decrd1*32+base)%base;
  }
  
  printf("[a]  = 0x");
  for(int j=0; j<2; j++){
    for(int i = 0; i < 8; ++i)
      printf("%.2x", msg[j][i]);
    printf(" ");
  }
    
  delete_gate_bootstrapping_secret_keyset(key);
  delete_gate_bootstrapping_parameters(params);
  delete_BaseBKeySwitchKey(ks_key);
  printf("\nverif: 0x%lx %lx \n", ciphertext[0], ciphertext[1]);
  printf("temps : %.5f\n", elapsed); 
  printf("\ndone\n");
  return 0;
}



int main2(){
  for(int i=0; i<16; i++){
    printf("%d, ", i&0b1100);
  }

  return 0;
}



int main3(){
   const int minimum_lambda = 110;
  static const int32_t N = 2048;
  static const int32_t k = 1;
  static const int32_t n = 1024;
  static const int32_t bk_l = 3;
  static const int32_t bk_Bgbit = 8;
  static const int32_t ks_basebit = 10;
  static const int32_t ks_length = 2;
  static const double ks_stdev = pow(5.6,-8);//standard deviation
  static const double bk_stdev = pow(9.6,-11);//standard deviation
  static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
  LweParams *params_in = new_LweParams(n, ks_stdev, max_stdev);
  TLweParams *params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
  TGswParams *params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

  TfheGarbageCollector::register_param(params_in);
  TfheGarbageCollector::register_param(params_accum);
  TfheGarbageCollector::register_param(params_bk);
  
  TFheGateBootstrappingParameterSet* params = new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
  uint32_t seed[] = {314, 1592, 657, 26363, 394, 4958, 4059, 3845};
  //mettre un bruit random
  tfhe_random_generator_setSeed(seed, 8);
  TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
  const LweKey * k_in = key->lwe_key;
  const TLweKey * k_out = &key->tgsw_key->tlwe_key;
  BaseBKeySwitchKey* ks_key = new_BaseBKeySwitchKey( key->lwe_key->params->n, 2, 10, 16, key->cloud.bk->accum_params);
  BaseBExtra::CreateKeySwitchKey(ks_key, k_in, k_out);
  printf("Etape 0 terminée\n");
  //(1) choisir le test vector
  u64 save[2]= {0xffffffffffffffff, 0x00000000000000ff};
  u64 rck[68];
  u64 plaintext[2]= { 0xffffffffffffffff, 0x00000000000000ff};
  word8 msg[2][8];
  encode(msg[0], plaintext[0]);
  encode(msg[1], plaintext[1]);
  vector<LweSample*> x[8];
  vector<LweSample*> y[8];
  Enc_tab(x, msg[0], key);
  Enc_tab(y, msg[1], key);

  //and_64_fhe(x, y, key, ks_key);
  xor_64_fhe(x, y, key, ks_key);

  word8 base =16;
   for(int i=0; i<8; i++){
      int32_t decr0 = lweSymDecrypt(x[i][0], key->lwe_key, 32);
      double decrd0 = t32tod(decr0);
      int32_t decr1 = lweSymDecrypt(x[i][1], key->lwe_key, 32);
      double decrd1 = t32tod(decr1);
      msg[0][i]= (int)(decrd0*32+base)%base*base + (int)(decrd1*32+base)%base;
      decr0 = lweSymDecrypt(y[i][0], key->lwe_key, 32);
      decrd0 = t32tod(decr0);
      decr1 = lweSymDecrypt(y[i][1], key->lwe_key, 32);
      decrd1 = t32tod(decr1);
      msg[1][i]= (int)(decrd0*32+base)%base*base + (int)(decrd1*32+base)%base;
  }
  

   printf("xor fhe\n");
   for(int i = 0; i < 64; ++i)
       printf("%ld", save[0]>>(63-i)&0b1);
   printf("\n");
     for(int k=0; k<64; k++)
       printf("%ld", save[1]>>(63-k)&0b1);
   printf("\n");
   for(int i = 0; i < 8; ++i)
     for(int k=0; k<8; k++)
       printf("%d", msg[0][i]>>(7-k)&0b1);
       printf("\n\n");
   
   /* for(int j=0; j<2; j++){
    for(int i = 0; i < 8; ++i)
      for(int k=0; k<8; k++)
	printf("%d", msg[j][i]>>(7-k)&0b1);
    printf(" ");
    }*/
  printf("\n\n");

  
  return 0;
}


