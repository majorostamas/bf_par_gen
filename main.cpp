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

#define RAWLEN 100

char masterSecretBytes[MODBYTES_B256_28];
octet masterSecret = {0, sizeof(masterSecretBytes), masterSecretBytes};


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

void extract(ECP *privateKey, octet *masterSecret, octet *ID) {
    char dst[256];
    octet DST = {0, sizeof(dst), dst};
    OCT_jstring(&DST,(char *)"BN254G1_XMD:SHA-256_SVDW_NU_MPIN");
    hashToPoint(privateKey, &DST, ID);
    BIG masterSecretAsBIG;
    BIG_fromBytes(masterSecretAsBIG, masterSecret->val);
    PAIR_G1mul(privateKey, masterSecretAsBIG);
}


void genParameters(){
    csprng RNG;                // Crypto Strong RNG
    ECP2 pPublic;
    char buffer[1024];
    FILE *fp;
    srand (time(NULL));
    char raw[RAWLEN];
    octet RAW = {0, sizeof(raw), raw};

    RAW.len = RAWLEN;
    for (int i = 0; i < RAWLEN; i++){
        RAW.val[i] = rand() % 256;
    }

    CREATE_CSPRNG(&RNG, &RAW);  

    init(&RNG, &pPublic, &masterSecret);

    OCT_toHex(&masterSecret, buffer);
    printf("Mastersecret: %s\n", buffer);
    fp = fopen("parameters/masterSecret", "w");//opening file  
    fprintf(fp, "%s", buffer);
    fclose(fp);//closing file
    
    char pPublicBytes[200];
    octet pPublicOctet = {0, sizeof(pPublicBytes), pPublicBytes};
    ECP2_toOctet(&pPublicOctet, &pPublic, false);
    OCT_toHex(&pPublicOctet, buffer);
    printf("Public parameters: %s\n", buffer);
    fp = fopen("parameters/pPublic", "w");//opening file  
    fprintf(fp, "%s", buffer);
    fclose(fp);//closing file
    
}

void extractKeys(){
    ECP privateKeyPC;
    ECP privateKeyESP;
    char IDBytesPC[100];
    octet ID_PC = {0, sizeof(IDBytesPC), IDBytesPC};
    char IDBytesESP[100];
    octet ID_ESP = {0, sizeof(IDBytesESP), IDBytesESP};
    char buffer[1024];
    FILE *fp;
    OCT_jstring(&ID_PC, (char *)"pcid"); 
    extract(&privateKeyPC, &masterSecret, &ID_PC);
    OCT_jstring(&ID_ESP, (char *)"espid");
    extract(&privateKeyESP, &masterSecret, &ID_ESP);
    
    
    char privateKeyPCBytes[100];
    octet privateKeyPCOctet = {0, sizeof(privateKeyPCBytes), privateKeyPCBytes};
    char privateKeyESPBytes[100];
    octet privateKeyESPOctet = {0, sizeof(privateKeyESPBytes), privateKeyESPBytes};
    
    ECP_toOctet(&privateKeyPCOctet, &privateKeyPC, false);
    ECP_toOctet(&privateKeyESPOctet, &privateKeyESP, false);
   
    
    OCT_toHex(&privateKeyPCOctet, buffer);
    printf("PC private key: %s\n", buffer);
    fp = fopen("parameters/privateKeyPC", "w");//opening file  
    fprintf(fp, "%s", buffer);
    fclose(fp);//closing file
    
    
    OCT_toHex(&privateKeyESPOctet, buffer);
    printf("ESP private key: %s\n", buffer);
    fp = fopen("parameters/privateKeyESP", "w");//opening file  
    fprintf(fp, "%s", buffer);
    fclose(fp);//closing file
}


int main(){
    genParameters();
    extractKeys();
}
