#include "core.h"
#include "ecp_BN254.h"
#include "ecp2_BN254.h"
#include "pair_BN254.h"
#include "randapi.h"

#include "utils.h"

#include <time.h>       /* time */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

using namespace core;
using namespace BN254;
using namespace B256_28;

/* create random secret S */
int BFIBE_BN254_RANDOM_GENERATE(csprng *RNG, octet* S) {
    BIG r, s;
    BIG_rcopy(r, CURVE_Order);
    BIG_randtrunc(s, r, 2 * CURVE_SECURITY_BN254, RNG);
    BIG_toBytes(S->val, s);
    S->len = MODBYTES_B256_28;
    return 0;
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
    concat.len = 2 * HASH_TYPE_BN254;

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

void read(octet *pPublicOctet, octet *privateKeyOctet){
   int i;
   FILE *fp;
   int sz;
   char *buffer = NULL;
   size_t size = 0;
   
   //PUBLIC PARAMETERS
   fp = fopen("parameters/pPublic", "r");
   fseek(fp, 0, SEEK_END); /* Go to end of file */
   size = ftell(fp);
   rewind(fp);
   buffer = (char*)malloc((size + 1) * sizeof(*buffer)); /* size + 1 byte for the \0 */
   fread(buffer, size, 1, fp); /* Read 1 chunk of size bytes from fp into buffer */
   buffer[size] = '\0';
   OCT_fromHex(pPublicOctet, buffer);
   fclose(fp);
   free(buffer);

   
   //PRIVATE KEY
   fp = fopen("parameters/privateKeyPC", "r"); 
   fseek(fp, 0, SEEK_END); /* Go to end of file */
   size = ftell(fp);
   rewind(fp);
   buffer = (char*)malloc((size + 1) * sizeof(*buffer)); /* size + 1 byte for the \0 */
   fread(buffer, size, 1, fp); /* Read 1 chunk of size bytes from fp into buffer */
   buffer[size] = '\0';
   OCT_fromHex(privateKeyOctet, buffer);
   fclose(fp);
   free(buffer);
}  

int main(){
    char pPublicBytes[200];
    char privateKeyPCBytes[100];
    char buffer[1024];
    
    octet pPublicOctet = {0, sizeof(pPublicBytes), pPublicBytes};
    octet privateKeyPCOctet = {0, sizeof(privateKeyPCBytes), privateKeyPCBytes}; 

    //Read public parameters and PC private key from file
    read(&pPublicOctet, &privateKeyPCOctet);
    OCT_toHex(&pPublicOctet, buffer);
    printf("Public parameters: %s\n", buffer);
    OCT_toHex(&privateKeyPCOctet, buffer);
    printf("PC private key: %s\n", buffer);
    
    ECP2 pPublic;
    ECP2_fromOctet(&pPublic, &pPublicOctet);
        
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
    
    char cipherVhex[2*HASH_TYPE_BN254];
    char cipherWhex[200];
    OCT_toHex(&cipherV, cipherVhex);
    OCT_toHex(&cipherW, cipherWhex);
    char cipherPointUOctetBytes[500];
    octet cipherPointUOctet = {0, sizeof(cipherPointUOctetBytes), cipherPointUOctetBytes};
    ECP2_toOctet(&cipherPointUOctet, &cipherPointU,false);
    char cipherPointUhex[1000];
    OCT_toHex(&cipherPointUOctet, cipherPointUhex);
    
    printf("CipherV: %s\n", cipherVhex);
    printf("CipherW: %s\n", cipherWhex);
    printf("cipherPointU: %s\n", cipherPointUhex);
    
    printf("Socket start\n");
    int sockfd;
    
    struct sockaddr_in     servaddr;
  
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
  
    memset(&servaddr, 0, sizeof(servaddr));
      
    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(1234);
    servaddr.sin_addr.s_addr = inet_addr("192.168.1.175");
      
    unsigned int n, len;
    
    // connect to server
    if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("\n Error : Connect Failed \n");
        exit(0);
    }
    
    //Send cipherV, cipherW and cipherPointU
    sendto(sockfd, cipherVhex, strlen(cipherVhex), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    sendto(sockfd, cipherWhex, strlen(cipherWhex), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    sendto(sockfd, cipherPointUhex, strlen(cipherPointUhex), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    printf("cipherV, cipherW and  cipherPointU sent.\n");
          
    n = recvfrom(sockfd, (char *)buffer, 1024, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
    buffer[n] = '\0';
    printf("Received message: %s\n", buffer);
    //decrypt(privateKey);
        
    close(sockfd);
}