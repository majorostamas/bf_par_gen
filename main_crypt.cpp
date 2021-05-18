#include "core.h"
#include "ecp_BN254.h"
#include "ecp2_BN254.h"
#include "pair_BN254.h"
#include "randapi.h"

#include "utils.h"

#include <time.h>       /* time */

using namespace core;
using namespace BN254;
using namespace B256_28;

char pPublicBytes[200];
char privateKeyPCBytes[100];

int ppublicsize;
int privatekeysize;


void OCT_print(octet *w)
{
    int i;
    unsigned char ch;
    for (i = 0; i < w->len; i++)
    {
        ch = w->val[i];
        printf("%02x", ch);
    }
    printf("\n");
}


/* create random secret S */
int BFIBE_BN254_RANDOM_GENERATE(csprng *RNG, octet* S) {
    BIG r, s;
    BIG_rcopy(r, CURVE_Order);
    BIG_randtrunc(s, r, 2 * CURVE_SECURITY_BN254, RNG);
    BIG_toBytes(S->val, s);
    S->len = MODBYTES_B256_28;
    return 0;
}

void init(csprng *RNG, ECP2 *pPublic, octet *masterSecret) {
    BFIBE_BN254_RANDOM_GENERATE(RNG, masterSecret);
    ECP2_generator(pPublic);
    BIG masterSecretAsBIG;  
    BIG_fromBytes(masterSecretAsBIG, masterSecret->val);
    PAIR_G2mul(pPublic, masterSecretAsBIG);
}

void encrypt(ECP2 *cipherPointU, octet *cipherV, octet *cipherW, octet *ID, octet *message, ECP2 *pPublic) {
    srand (time(NULL));
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};

    RAW.len = 100;
    for (int i = 0; i < 100; i++){
        RAW.val[i] = rand() % 256;
    }

    csprng RNG;                // Crypto Strong RNG
    CREATE_CSPRNG(&RNG, &RAW);
    
    
    char dst[256];
    octet DST = {0, sizeof(dst), dst};
    OCT_jstring(&DST,(char *)"BN254G1_XMD:SHA-256_SVDW_NU_MPIN");
    ECP pointQId;
    hashToPoint(&pointQId, &DST, ID);

    char rhoBytes[HASH_TYPE_BN254];
    octet rho = {0, sizeof(rhoBytes), rhoBytes};
    OCT_rand(&rho, &RNG, HASH_TYPE_BN254);

    char tBytes[HASH_TYPE_BN254];
    octet t = {0, sizeof(tBytes), tBytes};
    SPhash(MC_SHA2, HASH_TYPE_BN254, &t, message);

    char concatBytes[2 * HASH_TYPE_BN254];
    octet concat = {0, sizeof(concatBytes), concatBytes};
    for (int i = 0; i < HASH_TYPE_BN254; i++) {
        concat.val[i] = rho.val[i];
    }
    for (int i = 0; i < HASH_TYPE_BN254; i++) {
        concat.val[HASH_TYPE_BN254 + i] = t.val[i];
    }

    BIG l;
    hashToRange(l, &DST, &concat);

    ECP2_generator(cipherPointU);
    PAIR_G2mul(cipherPointU, l);

    FP12 theta;
    PAIR_ate(&theta, pPublic, &pointQId);
    PAIR_fexp(&theta);

    PAIR_GTpow(&theta, l);

    char zBytes[384];
    octet z = {0, sizeof(zBytes), zBytes};
    FP12_toOctet(&z, &theta);

    SPhash(MC_SHA2, HASH_TYPE_BN254, cipherV, &z);

    OCT_xor(cipherV, &rho);

    hashBytes(cipherW, message->len, &rho);

    OCT_xor(cipherW, message);
}

void decrypt(ECP2 *cipherPointU, octet *cipherV, octet *cipherW, ECP *privateKey) {
    FP12 theta;
    PAIR_ate(&theta, cipherPointU, privateKey);
    PAIR_fexp(&theta);

    char zBytes[384];
    octet z = {0, sizeof(zBytes), zBytes};
    FP12_toOctet(&z, &theta);

    char rhoBytes[HASH_TYPE_BN254];
    octet rho = {0, sizeof(rhoBytes), rhoBytes};
    SPhash(MC_SHA2, HASH_TYPE_BN254, &rho, &z);

    OCT_xor(&rho, cipherV);

    char messageBytes[100];
    octet message = {0, sizeof(messageBytes), messageBytes};
    hashBytes(&message, cipherW->len, &rho);

    OCT_xor(&message, cipherW);

    for(int i = 0; i < cipherW->len; i++) {
        printf("%c",*(message.val + i));
    }
    printf("\n");
}

void read(){
   int i;
   FILE *fp;
   int sz;
    
   //PUBLIC PARAMETERS
   fp = fopen("parameters/pPublic", "r"); 
   fseek(fp, 0L, SEEK_END);
   sz = ftell(fp);
   printf("%d\n",sz);
   fseek(fp, 0L, SEEK_SET);
   for(i=0; i<sz/2; i++){
        unsigned int val;
        fscanf(fp, "%02x", &val);
        pPublicBytes[i]=val;
   }
   fclose(fp);
   ppublicsize = sz/2;
   
   
   
   //PRIVATE KEY
   fp = fopen("parameters/privateKeyPC", "r"); 
   fseek(fp, 0L, SEEK_END);
   sz = ftell(fp);
   printf("%d\n",sz);
   fseek(fp, 0L, SEEK_SET);
   for(i=0; i<sz/2; i++){
        unsigned int val;
        fscanf(fp, "%02x", &val);
        privateKeyPCBytes[i]=val;
   }
   fclose(fp);
   privatekeysize = sz/2;
}  

int main(){
    //Read public parameters and PC private key from file
    read();
    
    octet pPublicOctet = {ppublicsize, sizeof(pPublicBytes), pPublicBytes};
    printf("Public parameters: ");
    OCT_print(&pPublicOctet);
    
    ECP2 pPublic;
    ECP2_fromOctet(&pPublic, &pPublicOctet);
    
    octet privateKeyPCOctet = {privatekeysize, sizeof(privateKeyPCBytes), privateKeyPCBytes};
    printf("PC private key: ");
    OCT_print(&privateKeyPCOctet);
    
    ECP privateKeyPC;
    ECP_fromOctet(&privateKeyPC, &privateKeyPCOctet);
    
    ECP2 cipherPointU;

    char cipherVBytes[HASH_TYPE_BN254];
    octet cipherV = {0, sizeof(cipherVBytes), cipherVBytes};

    char messageBytes[100];
    octet message = {0, sizeof(messageBytes), messageBytes};

    char cipherWBytes[100];
    octet cipherW = {0, sizeof(cipherWBytes), cipherWBytes};

    char IDBytes[100];
    octet ID = {0, sizeof(IDBytes), IDBytes};

    OCT_jstring(&ID, (char *)"pcid");
    OCT_jstring(&message, (char *)"Testmessage");

    encrypt(&cipherPointU, &cipherV, &cipherW, &ID, &message, &pPublic);
    decrypt(&cipherPointU, &cipherV, &cipherW, &privateKeyPC);
}