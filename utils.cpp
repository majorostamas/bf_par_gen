  
#include <math.h>

#include "FP_BN254.h"

#include "utils.h"

using namespace core;
using namespace BN254;
using namespace B256_28;

#define ROUNDUP(a,b) ((a)-1)/(b)+1

void hashToRange(BIG result, octet *DST, octet *s) {
    int k, m, L;
    char okm[512], fd[256];
    BIG q, r;
    DBIG dx;
    octet OKM = {0, sizeof(okm), okm};

    BIG_rcopy(q, Modulus);
    k=BIG_nbits(q);

    BIG_rcopy(r, CURVE_Order);
    m=BIG_nbits(r);

    L=ROUNDUP(k + ROUNDUP(m, 2), 8);

    XMD_Expand(MC_SHA2, HASH_TYPE_BN254, &OKM, L, DST, s);
    for (int j = 0; j < L; j++)
        fd[j] = OKM.val[j];

    BIG_dfromBytesLen(dx, fd, L);
    BIG_dmod(result, dx, q);
}

void hashToPoint(ECP *result, octet *DST, octet *ID) {
    char fd[256];
    BIG w;
    FP u;

    hashToRange(w, DST, ID);

    FP_nres(&u,w);
    ECP_map2point(result,&u);
    ECP_cfp(result);
    ECP_affine(result);
}

void hashBytes(octet *result, const int b, octet *p) {
  // Implementation of Algorithm 4.2.1 (HashBytes) in [RFC-5091].

  // Let \f$k = \mathrm{hashfcn}(p)\f$.
  char kBytes[HASH_TYPE_BN254];
  octet k = {0, sizeof(kBytes), kBytes};
  SPhash(MC_SHA2, HASH_TYPE_BN254, &k, p);

  // Let \f$h_0 = 00...00\f$, a string of null octets with a length of {@code
  // hashlen}.
  char hBytes[HASH_TYPE_BN254];
  octet h = {0, sizeof(hBytes), hBytes};
  for (int i = 0; i < HASH_TYPE_BN254; i++) {
    h.val[i] = 0;
  }

  // Let \f$l = \mathrm{Ceiling}(\frac{b}{\mathrm{hashlen}}).
  int l = (int)ceil((double)b / (double)HASH_TYPE_BN254);

  int generatedOctets = 0;
  int didGenerateEnough = 0;
  char concatBytes[2 * HASH_TYPE_BN254];
  octet concat = {0, sizeof(concatBytes), concatBytes};
  char resultPartBytes[HASH_TYPE_BN254];
  octet resultPart = {0, sizeof(resultPartBytes), resultPartBytes};
  // {@code For each i in 1 to l, do:}
  for (int i = 1; i <= l && !didGenerateEnough; i++) {
    // Let \f$h_i = \mathrm{hashfcn}(h_{i - 1}).
    SPhash(MC_SHA2, HASH_TYPE_BN254, &h, &h);

    // Let \f$r_i = \mathrm{hashfcn}(h_i || k)\f$, where \f$h_i || k\f$ is the
    // \f$(2 \cdot \mathrm{hashlen})\f$-octet concatenation of \f$h_i\f$ and
    // \f$k\f$.
    for (int j = 0; j < HASH_TYPE_BN254; j++) {
      concat.val[j] = h.val[j];
    }
    for (int j = 0; j < HASH_TYPE_BN254; j++) {
      concat.val[HASH_TYPE_BN254 + j] = k.val[j];
    }
    concat.len = 2 * HASH_TYPE_BN254;

    SPhash(MC_SHA2, HASH_TYPE_BN254, &resultPart, &concat);

    // Let \f$r = \mathrm{LeftmostOctets}(b, r_1 || ... || r_l)\f$, i.e.,
    // \f$r\f$ is formed as the concatenation of the \f$r_i\f$, truncated to the
    // desired number of octets.
    for (int j = 0; j < HASH_TYPE_BN254; j++) {
      if (generatedOctets + j < b) {
        result->val[generatedOctets + j] = resultPart.val[j];
      } else {
        didGenerateEnough = 1;
        break;
      }
    }
    generatedOctets += HASH_TYPE_BN254;
  }

  result->len = b;
}