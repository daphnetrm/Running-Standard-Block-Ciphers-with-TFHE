#include "clefia.h"
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
  
  
  //(1) choisir le chiffré pour les tests
  word32 key_tab [4]={0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100};
  word32 cleartext[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
  word32  wk_tab [4] ;//= {0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100};
  word32 ciphertext[4] = {0xde2bf2fd, 0x9b74aacd, 0xf1298555, 0x459494fd};
  word32 rcki_tab[36];
  key_scheduling(key_tab, wk_tab, rcki_tab);
  printf("Key Schedule terminé\n");
  
  //(2) Encodage sous forme de paquets de 8 nibbles = 32 bits
  word8 wk_decompo[4][8];
  word8 rcki_decompo[36][8];
  word8 message[4][8];
  for(int i=0; i<36;i++)
    encode(rcki_decompo[i],rcki_tab[i]);
  for(int i=0; i<4; i++){
    encode(message[i], cleartext[i]);
    encode(wk_decompo[i], wk_tab[i]);
  }
 
  //(3) Chiffrer les clefs et le message en homomorphe
  vector<LweSample*> wk_fhe[4][4];
  vector<LweSample*> rcki_fhe[36][4];
  vector<LweSample*> msg_fhe[4][4];
  for(int i=0; i<4; i++){
    Enc_tab(msg_fhe[i], message[i], key);
    Enc_tab(wk_fhe[i], wk_decompo[i], key);
  }
  for(int i = 0; i<36; i++)
    Enc_tab(rcki_fhe[i], rcki_decompo[i], key);
  printf("Chiffrement terminé\n");
  
  //(4) appliquer l'algo de chiffrement dans le domaine homomorphe
  struct timespec begin, end; 
  clock_gettime(CLOCK_REALTIME, &begin);
  encryption_fhe(msg_fhe, wk_fhe, rcki_fhe, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  long seconds = end.tv_sec - begin.tv_sec;
  long nanoseconds = end.tv_nsec - begin.tv_nsec;
  double elapsed = seconds + nanoseconds*1e-9;
  printf("Chiffrement symétrique terminé\n");
  //(7) déchiffrer et vérifier qu'il s'agit bien du bon chiffré symétrique.
  word8 base =16;
  for(int i=0; i<4; i++){
    for(int g = 0; g<4; g++){
      int32_t decr0 = lweSymDecrypt(msg_fhe[i][g][0], key->lwe_key, 32);
      double decrd0 = t32tod(decr0);
      int32_t decr1 = lweSymDecrypt(msg_fhe[i][g][1], key->lwe_key, 32);
      double decrd1 = t32tod(decr1);
      message[i][g]= (int)(decrd0*32+base)%base*base + (int)(decrd1*32+base)%base;
    }
  }
  printf("[a]  = 0x");
  for(int j=0; j<4; j++){
    for(int i = 0; i < 4; ++i)
      printf("%.2x", message[j][i]);
    printf(" ");
    }
  
  delete_gate_bootstrapping_secret_keyset(key);
  delete_gate_bootstrapping_parameters(params);
  delete_BaseBKeySwitchKey(ks_key);
  printf("\nverif: 0x%x %x %x %x\n", ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]);
  printf("temps : %.5f\n", elapsed); 
  printf("\ndone\n");
  
    return 0;
    }

int main42 (){
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
  tfhe_random_generator_setSeed(seed, 8);
  TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
  const LweKey * k_in = key->lwe_key;
  const TLweKey * k_out = &key->tgsw_key->tlwe_key;
  BaseBKeySwitchKey* ks_key = new_BaseBKeySwitchKey( key->lwe_key->params->n, 2, 10, 16, key->cloud.bk->accum_params);
  BaseBExtra::CreateKeySwitchKey(ks_key, k_in, k_out);
  printf("Etape 0 terminée\n");
  
  
  //(1) choisir le chiffré pour les tests
  word32 cleartext[4] = {0x00000101, 0x02020303, 0x04040505, 0x06060707};
  word8 message[4][8];
  for(int i=0; i<4; i++){
    encode(message[i], cleartext[i]);
  }
  vector<LweSample*> msg_fhe[4][4];
  for(int i=0; i<4; i++){
    Enc_tab(msg_fhe[i], message[i], key);
  }

  for(int i=0; i<4; i++){
    for(int j=0; j<4; j++)
      mul2_fhe(msg_fhe[i][j], msg_fhe[i][j], key, ks_key);
  }
  printf("Application de f terminée\n");
  //(7) déchiffrer et vérifier qu'il s'agit bien du bon chiffré symétrique.
  word8 base =16;
  for(int i=0; i<4; i++){
    for(int g = 0; g<4; g++){
      int32_t decr0 = lweSymDecrypt(msg_fhe[i][g][0], key->lwe_key, 32);
      double decrd0 = t32tod(decr0);
      int32_t decr1 = lweSymDecrypt(msg_fhe[i][g][1], key->lwe_key, 32);
      double decrd1 = t32tod(decr1);
      message[i][g]= (int)(decrd0*32+base)%base*base + (int)(decrd1*32+base)%base;
    }
  }
  printf("[a]  = 0x");
  for(int j=0; j<4; j++){
    for(int i = 0; i < 4; ++i)
      printf("%.2x", message[j][i]);
    printf(" ");
  }
  
  delete_gate_bootstrapping_secret_keyset(key);
  delete_gate_bootstrapping_parameters(params);
 
  printf("\ndone\n");
  
  return 0;
}


int main23(){
  /*
   printf("word8 T2_msb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",T2[i]/16);
  }
  printf("%d};\n\n",(T2[255]/16));
  printf("word8 T2_lsb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",(T2[i]%16));
  }
  printf("%d};\n\n",(T2[255]/16));
   printf("word8 T4_msb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",T4[i]/16);
  }
  printf("%d};\n\n",(T4[255]/16));
  printf("word8 T4_lsb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",(T4[i]%16));
  }
  printf("%d};\n\n",(T4[255]/16));
    printf("word8 T6_msb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",T6[i]/16);
  }
  printf("%d};\n\n",(T6[255]/16));
  printf("word8 T6_lsb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",(T6[i]%16));
  }
  printf("%d};\n\n",(T6[255]/16));
   printf("word8 T8_msb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",T8[i]/16);
  }
  printf("%d};\n\n",(T8[255]/16));
  printf("word8 T8_lsb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",(T8[i]%16));
  }
  printf("%d};\n\n",(T8[255]/16));
  printf("word8 Ta_msb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",Ta[i]/16);
  }
  printf("%d};\n\n",(Ta[255]/16));
  printf("word8 Ta_lsb[256] = { ");
  for(int i=0; i<255; ++i){
    printf("%d, ",(Ta[i]%16));
  }
  printf("%d};\n\n",(Ta[255]/16));
  */
  return 0;
}


