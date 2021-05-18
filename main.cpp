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

csprng RNG;                // Crypto Strong RNG
char masterSecretBytes[MODBYTES_B256_28];
octet masterSecret = {0, sizeof(masterSecretBytes), masterSecretBytes};
ECP2 pPublic;
char IDBytesPC[100];
octet ID_PC = {0, sizeof(IDBytesPC), IDBytesPC};
char IDBytesESP[100];
octet ID_ESP = {0, sizeof(IDBytesESP), IDBytesESP};
ECP privateKeyPC;
ECP privateKeyESP;

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
    int i;
    unsigned char ch;
    FILE *fp;
    srand (time(NULL));
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};

    RAW.len = 100;              // fake random seed source
    for (int i = 0; i < 100; i++){
        RAW.val[i] = rand() % 256;
    }

    CREATE_CSPRNG(&RNG, &RAW);  

    init(&RNG, &pPublic, &masterSecret);

    printf("Mastersecret: ");
    OCT_print(&masterSecret);
    fp = fopen("parameters/masterSecret", "w");//opening file  
    for (i = 0; i < masterSecret.len; i++)
    {
        ch = masterSecret.val[i];
        fprintf(fp, "%02x", ch);
    }
    fclose(fp);//closing file
    
    char pPublicBytes[200];
    octet pPublicOctet = {0, sizeof(pPublicBytes), pPublicBytes};
    ECP2_toOctet(&pPublicOctet, &pPublic, false);
    printf("Public parameters: ");
    OCT_print(&pPublicOctet);
    fp = fopen("parameters/pPublic", "w");//opening file  
    for (i = 0; i < pPublicOctet.len; i++)
    {
        ch = pPublicOctet.val[i];
        fprintf(fp, "%02x", ch);
    }
    fclose(fp);//closing file
    
}

void extractKeys(){
    int i;
    unsigned char ch;
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
    
    printf("PC private key: ");
    OCT_print(&privateKeyPCOctet);
    printf("ESP32 private key: ");
    OCT_print(&privateKeyESPOctet);
    
    fp = fopen("parameters/privateKeyPC", "w");//opening file  

    for (i = 0; i < privateKeyPCOctet.len; i++)
    {
        ch = privateKeyPCOctet.val[i];
        fprintf(fp, "%02x", ch);
    }
    fclose(fp);//closing file
    
    
    fp = fopen("parameters/privateKeyESP", "w");//opening file  

    for (i = 0; i < privateKeyESPOctet.len; i++)
    {
        ch = privateKeyESPOctet.val[i];
        fprintf(fp, "%02x", ch);
    }
    fclose(fp);//closing file
}


int main(){
  genParameters();
  extractKeys();
}
