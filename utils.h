#include "core.h"
#include "big_B256_28.h"
#include "ECP_BN254.h"

using namespace core;
using namespace BN254;
using namespace B256_28;

void hashToRange(BIG result, octet *DST, octet *s);

void hashToPoint(ECP *result, octet *DST, octet *ID);

void hashBytes(octet *result, const int b, octet *p);