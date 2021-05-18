/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* CORE basic functions for BIG type */
/* SU=m, SU is Stack Usage */

#include "big_B256_28.h"

//int B256_28::BIGMULS=0;
//int B256_28::BIGSQRS=0;

/* test a=0? */
int B256_28::BIG_iszilch(BIG a)
{
    int i;
    chunk d=0;
    for (i = 0; i < NLEN_B256_28; i++)
        d|=a[i];
    return (1 & ((d-1)>>BASEBITS_B256_28));
}

/* test a=1? */
int B256_28::BIG_isunity(BIG a)
{
    int i;
    chunk d=0;
    for (i = 1; i < NLEN_B256_28; i++)
        d|=a[i];
    return (1 & ((d-1)>>BASEBITS_B256_28) & (((a[0]^1)-1)>>BASEBITS_B256_28));
}

/* test a=0? */
int B256_28::BIG_diszilch(DBIG a)
{
    int i;
    chunk d=0;
    for (i = 0; i < DNLEN_B256_28; i++)
        d|=a[i];
    return (1 & ((d-1)>>BASEBITS_B256_28));
}

/* SU= 56 */
/* output a */
void B256_28::BIG_output(BIG a)
{
    BIG b;
    int i, len;
    len = BIG_nbits(a);
    if (len % 4 == 0) len /= 4;
    else
    {
        len /= 4;
        len++;
    }
    if (len < MODBYTES_B256_28 * 2) len = MODBYTES_B256_28 * 2;

    for (i = len - 1; i >= 0; i--)
    {
        BIG_copy(b, a);
        BIG_shr(b, i * 4);
        printf("%01x", (unsigned int) b[0] & 15);
    }
}

/* SU= 16 */
void B256_28::BIG_rawoutput(BIG a)
{
    int i;
    printf("(");
    for (i = 0; i < NLEN_B256_28 - 1; i++)
#if CHUNK==64
        printf("%jx,", (uintmax_t) a[i]);
    printf("%jx)", (uintmax_t) a[NLEN_B256_28 - 1]);
#else
        printf("%x,", (unsigned int) a[i]);
    printf("%x)", (unsigned int) a[NLEN_B256_28 - 1]);
#endif
}

/* Swap a and b if d=1 */
void B256_28::BIG_cswap(BIG a, BIG b, int d)
{
    int i;
    chunk t, c = d;
    c = ~(c - 1);
#ifdef DEBUG_NORM
    for (i = 0; i < NLEN_B256_28 + 2; i++)
#else
    for (i = 0; i < NLEN_B256_28; i++)
#endif
    {
        t = c & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/* Move g to f if d=1 */
void B256_28::BIG_cmove(BIG f, BIG g, int d)
{
    int i;
    chunk b = (chunk) - d;
#ifdef DEBUG_NORM
    for (i = 0; i < NLEN_B256_28 + 2; i++)
#else
    for (i = 0; i < NLEN_B256_28; i++)
#endif
    {
        f[i] ^= (f[i] ^ g[i])&b;
    }
}

/* Move g to f if d=1 */
void B256_28::BIG_dcmove(DBIG f, DBIG g, int d)
{
    int i;
    chunk b = (chunk) - d;
#ifdef DEBUG_NORM
    for (i = 0; i < DNLEN_B256_28 + 2; i++)
#else
    for (i = 0; i < DNLEN_B256_28; i++)
#endif
    {
        f[i] ^= (f[i] ^ g[i])&b;
    }
}

/* convert BIG to/from bytes */
/* SU= 64 */
void B256_28::BIG_toBytes(char *b, BIG a)
{
    int i;
    BIG c;
    BIG_copy(c, a);
    BIG_norm(c);
    for (i = MODBYTES_B256_28 - 1; i >= 0; i--)
    {
        b[i] = c[0] & 0xff;
        BIG_fshr(c, 8);
    }
}

/* SU= 16 */
void B256_28::BIG_fromBytes(BIG a, char *b)
{
    int i;
    BIG_zero(a);
    for (i = 0; i < MODBYTES_B256_28; i++)
    {
        BIG_fshl(a, 8);
        a[0] += (int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[MPV_B256_28] = 1; a[MNV_B256_28] = 0;
#endif
}

void B256_28::BIG_fromBytesLen(BIG a, char *b, int s)
{
    int i, len = s;
    BIG_zero(a);

    if (len > MODBYTES_B256_28) len = MODBYTES_B256_28;
    for (i = 0; i < len; i++)
    {
        BIG_fshl(a, 8);
        a[0] += (int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[MPV_B256_28] = 1; a[MNV_B256_28] = 0;
#endif
}



/* SU= 88 */
void B256_28::BIG_doutput(DBIG a)
{
    DBIG b;
    int i, len;
    BIG_dnorm(a);
    len = BIG_dnbits(a);
    if (len % 4 == 0) len /= 4;
    else
    {
        len /= 4;
        len++;
    }

    for (i = len - 1; i >= 0; i--)
    {
        BIG_dcopy(b, a);
        BIG_dshr(b, i * 4);
        printf("%01x", (unsigned int) b[0] & 15);
    }
}


void B256_28::BIG_drawoutput(DBIG a)
{
    int i;
    printf("(");
    for (i = 0; i < DNLEN_B256_28 - 1; i++)
#if CHUNK==64
        printf("%jx,", (uintmax_t) a[i]);
    printf("%jx)", (uintmax_t) a[DNLEN_B256_28 - 1]);
#else
        printf("%x,", (unsigned int) a[i]);
    printf("%x)", (unsigned int) a[DNLEN_B256_28 - 1]);
#endif
}

/* Copy b=a */
void B256_28::BIG_copy(BIG b, BIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[MPV_B256_28] = a[MPV_B256_28];
    b[MNV_B256_28] = a[MNV_B256_28];
#endif
}

/* Copy from ROM b=a */
void B256_28::BIG_rcopy(BIG b, const BIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[MPV_B256_28] = 1; b[MNV_B256_28] = 0;
#endif
}

/* double length DBIG copy b=a */
void B256_28::BIG_dcopy(DBIG b, DBIG a)
{
    int i;
    for (i = 0; i < DNLEN_B256_28; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[DMPV_B256_28] = a[DMPV_B256_28];
    b[DMNV_B256_28] = a[DMNV_B256_28];
#endif
}

/* Copy BIG to bottom half of DBIG */
void B256_28::BIG_dscopy(DBIG b, BIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28 - 1; i++)
        b[i] = a[i];

    b[NLEN_B256_28 - 1] = a[NLEN_B256_28 - 1] & BMASK_B256_28; /* top word normalized */
    b[NLEN_B256_28] = a[NLEN_B256_28 - 1] >> BASEBITS_B256_28;

    for (i = NLEN_B256_28 + 1; i < DNLEN_B256_28; i++) b[i] = 0;
#ifdef DEBUG_NORM
    b[DMPV_B256_28] = a[MPV_B256_28];
    b[DMNV_B256_28] = a[MNV_B256_28];
#endif
}

/* Copy BIG to top half of DBIG */
void B256_28::BIG_dsucopy(DBIG b, BIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        b[i] = 0;
    for (i = NLEN_B256_28; i < DNLEN_B256_28; i++)
        b[i] = a[i - NLEN_B256_28];
#ifdef DEBUG_NORM
    b[DMPV_B256_28] = a[MPV_B256_28];
    b[DMNV_B256_28] = a[MNV_B256_28];
#endif
}

/* Copy bottom half of DBIG to BIG */
void B256_28::BIG_sdcopy(BIG b, DBIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[MPV_B256_28] = a[DMPV_B256_28];
    b[MNV_B256_28] = a[DMNV_B256_28];
#endif
}

/* Copy top half of DBIG to BIG */
void B256_28::BIG_sducopy(BIG b, DBIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        b[i] = a[i + NLEN_B256_28];
#ifdef DEBUG_NORM
    b[MPV_B256_28] = a[DMPV_B256_28];
    b[MNV_B256_28] = a[DMNV_B256_28];

#endif
}

/* Set a=0 */
void B256_28::BIG_zero(BIG a)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        a[i] = 0;
#ifdef DEBUG_NORM
    a[MPV_B256_28] = a[MNV_B256_28] = 0;
#endif
}

void B256_28::BIG_dzero(DBIG a)
{
    int i;
    for (i = 0; i < DNLEN_B256_28; i++)
        a[i] = 0;
#ifdef DEBUG_NORM
    a[DMPV_B256_28] = a[DMNV_B256_28] = 0;
#endif
}

/* set a=1 */
void B256_28::BIG_one(BIG a)
{
    int i;
    a[0] = 1;
    for (i = 1; i < NLEN_B256_28; i++)
        a[i] = 0;
#ifdef DEBUG_NORM
    a[MPV_B256_28] = 1;
    a[MNV_B256_28] = 0;
#endif
}

/* Set c=a+b */
/* SU= 8 */
void B256_28::BIG_add(BIG c, BIG a, BIG b)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        c[i] = a[i] + b[i];
#ifdef DEBUG_NORM
    c[MPV_B256_28] = a[MPV_B256_28] + b[MPV_B256_28];
    c[MNV_B256_28] = a[MNV_B256_28] + b[MNV_B256_28];
    if (c[MPV_B256_28] > NEXCESS_B256_28)  printf("add problem - positive digit overflow %d\n", (int)c[MPV_B256_28]);
    if (c[MNV_B256_28] > NEXCESS_B256_28)  printf("add problem - negative digit overflow %d\n", (int)c[MNV_B256_28]);

#endif
}

/* Set c=a or b */
/* SU= 8 */
void B256_28::BIG_or(BIG c, BIG a, BIG b)
{
    int i;
    BIG_norm(a);
    BIG_norm(b);
    for (i = 0; i < NLEN_B256_28; i++)
        c[i] = a[i] | b[i];
#ifdef DEBUG_NORM
    c[MPV_B256_28] = 1;
    c[MNV_B256_28] = 0;
#endif

}


/* Set c=c+d */
void B256_28::BIG_inc(BIG c, int d)
{
    BIG_norm(c);
    c[0] += (chunk)d;
#ifdef DEBUG_NORM
    c[MPV_B256_28] += 1;
#endif
}

/* Set c=a-b */
/* SU= 8 */
void B256_28::BIG_sub(BIG c, BIG a, BIG b)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++)
        c[i] = a[i] - b[i];
#ifdef DEBUG_NORM
    c[MPV_B256_28] = a[MPV_B256_28] + b[MNV_B256_28];
    c[MNV_B256_28] = a[MNV_B256_28] + b[MPV_B256_28];
    if (c[MPV_B256_28] > NEXCESS_B256_28)  printf("sub problem - positive digit overflow %d\n", (int)c[MPV_B256_28]);
    if (c[MNV_B256_28] > NEXCESS_B256_28)  printf("sub problem - negative digit overflow %d\n", (int)c[MNV_B256_28]);

#endif
}

/* SU= 8 */

void B256_28::BIG_dsub(DBIG c, DBIG a, DBIG b)
{
    int i;
    for (i = 0; i < DNLEN_B256_28; i++)
        c[i] = a[i] - b[i];
#ifdef DEBUG_NORM
    c[DMPV_B256_28] = a[DMPV_B256_28] + b[DMNV_B256_28];
    c[DMNV_B256_28] = a[DMNV_B256_28] + b[DMPV_B256_28];
    if (c[DMPV_B256_28] > NEXCESS_B256_28)  printf("double sub problem - positive digit overflow %d\n", (int)c[DMPV_B256_28]);
    if (c[DMNV_B256_28] > NEXCESS_B256_28)  printf("double sub problem - negative digit overflow %d\n", (int)c[DMNV_B256_28]);
#endif
}

void B256_28::BIG_dadd(DBIG c, DBIG a, DBIG b)
{
    int i;
    for (i = 0; i < DNLEN_B256_28; i++)
        c[i] = a[i] + b[i];
#ifdef DEBUG_NORM
    c[DMPV_B256_28] = a[DMPV_B256_28] + b[DMNV_B256_28];
    c[DMNV_B256_28] = a[DMNV_B256_28] + b[DMPV_B256_28];
    if (c[DMPV_B256_28] > NEXCESS_B256_28)  printf("double add problem - positive digit overflow %d\n", (int)c[DMPV_B256_28]);
    if (c[DMNV_B256_28] > NEXCESS_B256_28)  printf("double add problem - negative digit overflow %d\n", (int)c[DMNV_B256_28]);
#endif
}

/* Set c=c-1 */
void B256_28::BIG_dec(BIG c, int d)
{
    BIG_norm(c);
    c[0] -= (chunk)d;
#ifdef DEBUG_NORM
    c[MNV_B256_28] += 1;
#endif
}

/* multiplication r=a*c by c<=NEXCESS_B256_28 */
void B256_28::BIG_imul(BIG r, BIG a, int c)
{
    int i;
    for (i = 0; i < NLEN_B256_28; i++) r[i] = a[i] * c;
#ifdef DEBUG_NORM
    r[MPV_B256_28] = a[MPV_B256_28] * c;
    r[MNV_B256_28] = a[MNV_B256_28] * c;
    if (r[MPV_B256_28] > NEXCESS_B256_28)  printf("int mul problem - positive digit overflow %d\n", (int)r[MPV_B256_28]);
    if (r[MNV_B256_28] > NEXCESS_B256_28)  printf("int mul problem - negative digit overflow %d\n", (int)r[MNV_B256_28]);

#endif
}

/* multiplication r=a*c by larger integer - c<=FEXCESS */
/* SU= 24 */
chunk B256_28::BIG_pmul(BIG r, BIG a, int c)
{
    int i;
    chunk ak, carry = 0;
    for (i = 0; i < NLEN_B256_28; i++)
    {
        ak = a[i];
        r[i] = 0;
        carry = muladd(ak, (chunk)c, carry, &r[i]);
    }
#ifdef DEBUG_NORM
    r[MPV_B256_28] = 1;
    r[MNV_B256_28] = 0;
#endif
    return carry;
}

/* r/=3 */
/* SU= 16 */
/*
int B256_28::BIG_div3(BIG r)
{
    int i;
    chunk ak,base,carry=0;
    BIG_norm(r);
    base=((chunk)1<<BASEBITS_B256_28);
    for (i=NLEN_B256_28-1; i>=0; i--)
    {
        ak=(carry*base+r[i]);
        r[i]=ak/3;
        carry=ak%3;
    }
    return (int)carry;
}
*/
/* multiplication c=a*b by even larger integer b>FEXCESS, resulting in DBIG */
/* SU= 24 */
void B256_28::BIG_pxmul(DBIG c, BIG a, int b)
{
    int j;
    chunk carry;
    BIG_dzero(c);
    carry = 0;
    for (j = 0; j < NLEN_B256_28; j++)
        carry = muladd(a[j], (chunk)b, carry, &c[j]);
    c[NLEN_B256_28] = carry;
#ifdef DEBUG_NORM
    c[DMPV_B256_28] = 1;
    c[DMNV_B256_28] = 0;
#endif
}

/* .. if you know the result will fit in a BIG, c must be distinct from a and b */
/* SU= 40 */
void B256_28::BIG_smul(BIG c, BIG a, BIG b)
{
    int i, j;
    chunk carry;

    BIG_zero(c);
    for (i = 0; i < NLEN_B256_28; i++)
    {
        carry = 0;
        for (j = 0; j < NLEN_B256_28; j++)
        {
            if (i + j < NLEN_B256_28)
                carry = muladd(a[i], b[j], carry, &c[i + j]);
        }
    }
#ifdef DEBUG_NORM
    c[MPV_B256_28] = 1;
    c[MNV_B256_28] = 0;
#endif

}

/* Set c=a*b */
/* SU= 72 */
void B256_28::BIG_mul(DBIG c, BIG a, BIG b)
{
    int i,k;
#ifdef dchunk
    dchunk co,t;
    dchunk s;
    dchunk d[NLEN_B256_28];
    int m;
#endif

//B256_28::BIGMULS++;

#ifdef DEBUG_NORM
    if ((a[MPV_B256_28] != 1 && a[MPV_B256_28] != 0) || a[MNV_B256_28] != 0) printf("First input to mul not normed\n");
    if ((b[MPV_B256_28] != 1 && b[MPV_B256_28] != 0) || b[MNV_B256_28] != 0) printf("Second input to mul not normed\n");
#endif

    /* Faster to Combafy it.. Let the compiler unroll the loops! */

#ifdef COMBA

    /* faster psuedo-Karatsuba method */
#ifdef UNWOUND

#ifdef USE_KARATSUBA

    	d[0]=(dchunk)a[0]*b[0];
	d[1]=(dchunk)a[1]*b[1];
	d[2]=(dchunk)a[2]*b[2];
	d[3]=(dchunk)a[3]*b[3];
	d[4]=(dchunk)a[4]*b[4];
	d[5]=(dchunk)a[5]*b[5];
	d[6]=(dchunk)a[6]*b[6];
	d[7]=(dchunk)a[7]*b[7];
	d[8]=(dchunk)a[8]*b[8];
	d[9]=(dchunk)a[9]*b[9];

	s=d[0];
	t = s; c[0]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28;
	s+=d[1]; t=co+s +(dchunk)(a[1]-a[0])*(b[0]-b[1]); c[1]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[2]; t=co+s +(dchunk)(a[2]-a[0])*(b[0]-b[2]); c[2]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[3]; t=co+s +(dchunk)(a[3]-a[0])*(b[0]-b[3])+(dchunk)(a[2]-a[1])*(b[1]-b[2]); c[3]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[4]; t=co+s +(dchunk)(a[4]-a[0])*(b[0]-b[4])+(dchunk)(a[3]-a[1])*(b[1]-b[3]); c[4]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[5]; t=co+s +(dchunk)(a[5]-a[0])*(b[0]-b[5])+(dchunk)(a[4]-a[1])*(b[1]-b[4])+(dchunk)(a[3]-a[2])*(b[2]-b[3]); c[5]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[6]; t=co+s +(dchunk)(a[6]-a[0])*(b[0]-b[6])+(dchunk)(a[5]-a[1])*(b[1]-b[5])+(dchunk)(a[4]-a[2])*(b[2]-b[4]); c[6]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[7]; t=co+s +(dchunk)(a[7]-a[0])*(b[0]-b[7])+(dchunk)(a[6]-a[1])*(b[1]-b[6])+(dchunk)(a[5]-a[2])*(b[2]-b[5])+(dchunk)(a[4]-a[3])*(b[3]-b[4]); c[7]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[8]; t=co+s +(dchunk)(a[8]-a[0])*(b[0]-b[8])+(dchunk)(a[7]-a[1])*(b[1]-b[7])+(dchunk)(a[6]-a[2])*(b[2]-b[6])+(dchunk)(a[5]-a[3])*(b[3]-b[5]); c[8]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s+=d[9]; t=co+s +(dchunk)(a[9]-a[0])*(b[0]-b[9])+(dchunk)(a[8]-a[1])*(b[1]-b[8])+(dchunk)(a[7]-a[2])*(b[2]-b[7])+(dchunk)(a[6]-a[3])*(b[3]-b[6])+(dchunk)(a[5]-a[4])*(b[4]-b[5]); c[9]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 

	s-=d[0]; t=co+s +(dchunk)(a[9]-a[1])*(b[1]-b[9])+(dchunk)(a[8]-a[2])*(b[2]-b[8])+(dchunk)(a[7]-a[3])*(b[3]-b[7])+(dchunk)(a[6]-a[4])*(b[4]-b[6]); c[10]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[1]; t=co+s +(dchunk)(a[9]-a[2])*(b[2]-b[9])+(dchunk)(a[8]-a[3])*(b[3]-b[8])+(dchunk)(a[7]-a[4])*(b[4]-b[7])+(dchunk)(a[6]-a[5])*(b[5]-b[6]); c[11]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[2]; t=co+s +(dchunk)(a[9]-a[3])*(b[3]-b[9])+(dchunk)(a[8]-a[4])*(b[4]-b[8])+(dchunk)(a[7]-a[5])*(b[5]-b[7]); c[12]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[3]; t=co+s +(dchunk)(a[9]-a[4])*(b[4]-b[9])+(dchunk)(a[8]-a[5])*(b[5]-b[8])+(dchunk)(a[7]-a[6])*(b[6]-b[7]); c[13]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[4]; t=co+s +(dchunk)(a[9]-a[5])*(b[5]-b[9])+(dchunk)(a[8]-a[6])*(b[6]-b[8]); c[14]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[5]; t=co+s +(dchunk)(a[9]-a[6])*(b[6]-b[9])+(dchunk)(a[8]-a[7])*(b[7]-b[8]); c[15]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[6]; t=co+s +(dchunk)(a[9]-a[7])*(b[7]-b[9]); c[16]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[7]; t=co+s +(dchunk)(a[9]-a[8])*(b[8]-b[9]); c[17]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	s-=d[8]; t=co+s ; c[18]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	c[19]=(chunk)co;


#else

    	t=(dchunk)a[0]*b[0]; c[0]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[1]+(dchunk)a[1]*b[0]; c[1]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[2]+(dchunk)a[1]*b[1]+(dchunk)a[2]*b[0]; c[2]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[3]+(dchunk)a[1]*b[2]+(dchunk)a[2]*b[1]+(dchunk)a[3]*b[0]; c[3]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[4]+(dchunk)a[1]*b[3]+(dchunk)a[2]*b[2]+(dchunk)a[3]*b[1]+(dchunk)a[4]*b[0]; c[4]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[5]+(dchunk)a[1]*b[4]+(dchunk)a[2]*b[3]+(dchunk)a[3]*b[2]+(dchunk)a[4]*b[1]+(dchunk)a[5]*b[0]; c[5]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[6]+(dchunk)a[1]*b[5]+(dchunk)a[2]*b[4]+(dchunk)a[3]*b[3]+(dchunk)a[4]*b[2]+(dchunk)a[5]*b[1]+(dchunk)a[6]*b[0]; c[6]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[7]+(dchunk)a[1]*b[6]+(dchunk)a[2]*b[5]+(dchunk)a[3]*b[4]+(dchunk)a[4]*b[3]+(dchunk)a[5]*b[2]+(dchunk)a[6]*b[1]+(dchunk)a[7]*b[0]; c[7]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[8]+(dchunk)a[1]*b[7]+(dchunk)a[2]*b[6]+(dchunk)a[3]*b[5]+(dchunk)a[4]*b[4]+(dchunk)a[5]*b[3]+(dchunk)a[6]*b[2]+(dchunk)a[7]*b[1]+(dchunk)a[8]*b[0]; c[8]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[0]*b[9]+(dchunk)a[1]*b[8]+(dchunk)a[2]*b[7]+(dchunk)a[3]*b[6]+(dchunk)a[4]*b[5]+(dchunk)a[5]*b[4]+(dchunk)a[6]*b[3]+(dchunk)a[7]*b[2]+(dchunk)a[8]*b[1]+(dchunk)a[9]*b[0]; c[9]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[1]*b[9]+(dchunk)a[2]*b[8]+(dchunk)a[3]*b[7]+(dchunk)a[4]*b[6]+(dchunk)a[5]*b[5]+(dchunk)a[6]*b[4]+(dchunk)a[7]*b[3]+(dchunk)a[8]*b[2]+(dchunk)a[9]*b[1]; c[10]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[2]*b[9]+(dchunk)a[3]*b[8]+(dchunk)a[4]*b[7]+(dchunk)a[5]*b[6]+(dchunk)a[6]*b[5]+(dchunk)a[7]*b[4]+(dchunk)a[8]*b[3]+(dchunk)a[9]*b[2]; c[11]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[3]*b[9]+(dchunk)a[4]*b[8]+(dchunk)a[5]*b[7]+(dchunk)a[6]*b[6]+(dchunk)a[7]*b[5]+(dchunk)a[8]*b[4]+(dchunk)a[9]*b[3]; c[12]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[4]*b[9]+(dchunk)a[5]*b[8]+(dchunk)a[6]*b[7]+(dchunk)a[7]*b[6]+(dchunk)a[8]*b[5]+(dchunk)a[9]*b[4]; c[13]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[5]*b[9]+(dchunk)a[6]*b[8]+(dchunk)a[7]*b[7]+(dchunk)a[8]*b[6]+(dchunk)a[9]*b[5]; c[14]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[6]*b[9]+(dchunk)a[7]*b[8]+(dchunk)a[8]*b[7]+(dchunk)a[9]*b[6]; c[15]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[7]*b[9]+(dchunk)a[8]*b[8]+(dchunk)a[9]*b[7]; c[16]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[8]*b[9]+(dchunk)a[9]*b[8]; c[17]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	t=t+(dchunk)a[9]*b[9]; c[18]=(chunk)t & BMASK_B256_28; t=t>>BASEBITS_B256_28;
	c[19]=(chunk)t;


#endif

#else

#ifndef USE_KARATSUBA

    t=(dchunk)a[0]*b[0];
    c[0]=(chunk)t & BMASK_B256_28;
    t = t >> BASEBITS_B256_28;
    for (i=1;i<NLEN_B256_28;i++)
    {
        k=0; 
        while (k<=i) {t+=(dchunk)a[k]*b[i-k]; k++;}
        c[i]=(chunk)t & BMASK_B256_28;
        t = t >> BASEBITS_B256_28;
    }

    for (i=NLEN_B256_28;i<2*NLEN_B256_28-1;i++)
    {
        k=i-(NLEN_B256_28-1);
        while (k<=NLEN_B256_28-1) {t+=(dchunk)a[k]*b[i-k]; k++;}
        c[i]=(chunk)t & BMASK_B256_28;
        t = t >> BASEBITS_B256_28;
    }

    c[2 * NLEN_B256_28 - 1] = (chunk)t;
#else

    for (i = 0; i < NLEN_B256_28; i++)
        d[i] = (dchunk)a[i] * b[i];

    s = d[0];
    t = s;
    c[0] = (chunk)t & BMASK_B256_28;
    t = t >> BASEBITS_B256_28;

    for (k = 1; k < NLEN_B256_28; k++)
    {
        s += d[k];
        t += s;
        /*for (i = k; i >= 1 + k / 2; i--) This causes a huge slow down! gcc/g++ optimizer problem (I think) */
        for (i=1+k/2;i<=k;i++) t += (dchunk)(a[i] - a[k - i]) * (b[k - i] - b[i]);
        c[k] = (chunk)t & BMASK_B256_28;
        t = t >> BASEBITS_B256_28;
    }
    for (k = NLEN_B256_28; k < 2 * NLEN_B256_28 - 1; k++)
    {
        s -= d[k - NLEN_B256_28];
        t += s;
        for (i=1+k/2;i<NLEN_B256_28;i++) t += (dchunk)(a[i] - a[k - i]) * (b[k - i] - b[i]);
        c[k] = (chunk)t & BMASK_B256_28;
        t = t >> BASEBITS_B256_28;
    }
    c[2 * NLEN_B256_28 - 1] = (chunk)t;
#endif
#endif

#else
    int j;
    chunk carry;
    BIG_dzero(c);
    for (i = 0; i < NLEN_B256_28; i++)
    {
        carry = 0;
        for (j = 0; j < NLEN_B256_28; j++)
            carry = muladd(a[i], b[j], carry, &c[i + j]);

        c[NLEN_B256_28 + i] = carry;
    }

#endif

#ifdef DEBUG_NORM
    c[DMPV_B256_28] = 1;
    c[DMNV_B256_28] = 0;
#endif
}

/* Set c=a*a */
/* SU= 80 */
void B256_28::BIG_sqr(DBIG c, BIG a)
{
    int i, j;
#ifdef dchunk
    dchunk t, co;
#endif
//B256_28::BIGSQRS++;
#ifdef DEBUG_NORM
    if ((a[MPV_B256_28] != 1 && a[MPV_B256_28] != 0) || a[MNV_B256_28] != 0) printf("Input to sqr not normed\n");
#endif
    /* Note 2*a[i] in loop below and extra addition */

#ifdef COMBA

#ifdef UNWOUND

    
	t=(dchunk)a[0]*a[0]; c[0]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28;
	t= +(dchunk)a[1]*a[0]; t+=t; t+=co; c[1]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[2]*a[0]; t+=t; t+=co; t+=(dchunk)a[1]*a[1]; c[2]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[3]*a[0]+(dchunk)a[2]*a[1]; t+=t; t+=co; c[3]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[4]*a[0]+(dchunk)a[3]*a[1]; t+=t; t+=co; t+=(dchunk)a[2]*a[2]; c[4]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[5]*a[0]+(dchunk)a[4]*a[1]+(dchunk)a[3]*a[2]; t+=t; t+=co; c[5]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[6]*a[0]+(dchunk)a[5]*a[1]+(dchunk)a[4]*a[2]; t+=t; t+=co; t+=(dchunk)a[3]*a[3]; c[6]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[7]*a[0]+(dchunk)a[6]*a[1]+(dchunk)a[5]*a[2]+(dchunk)a[4]*a[3]; t+=t; t+=co; c[7]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[8]*a[0]+(dchunk)a[7]*a[1]+(dchunk)a[6]*a[2]+(dchunk)a[5]*a[3]; t+=t; t+=co; t+=(dchunk)a[4]*a[4]; c[8]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[0]+(dchunk)a[8]*a[1]+(dchunk)a[7]*a[2]+(dchunk)a[6]*a[3]+(dchunk)a[5]*a[4]; t+=t; t+=co; c[9]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 

	t= +(dchunk)a[9]*a[1]+(dchunk)a[8]*a[2]+(dchunk)a[7]*a[3]+(dchunk)a[6]*a[4]; t+=t; t+=co; t+=(dchunk)a[5]*a[5]; c[10]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[2]+(dchunk)a[8]*a[3]+(dchunk)a[7]*a[4]+(dchunk)a[6]*a[5]; t+=t; t+=co; c[11]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[3]+(dchunk)a[8]*a[4]+(dchunk)a[7]*a[5]; t+=t; t+=co; t+=(dchunk)a[6]*a[6]; c[12]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[4]+(dchunk)a[8]*a[5]+(dchunk)a[7]*a[6]; t+=t; t+=co; c[13]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[5]+(dchunk)a[8]*a[6]; t+=t; t+=co; t+=(dchunk)a[7]*a[7]; c[14]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[6]+(dchunk)a[8]*a[7]; t+=t; t+=co; c[15]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[7]; t+=t; t+=co; t+=(dchunk)a[8]*a[8]; c[16]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t= +(dchunk)a[9]*a[8]; t+=t; t+=co; c[17]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
	t=co; t+=(dchunk)a[9]*a[9]; c[18]=(chunk)t&BMASK_B256_28; co=t>>BASEBITS_B256_28; 
 	c[19]=(chunk)co;


#else


    t = (dchunk)a[0] * a[0];
    c[0] = (chunk)t & BMASK_B256_28;
    co = t >> BASEBITS_B256_28;

    for (j = 1; j < NLEN_B256_28 - 1; )
    {
        t = (dchunk)a[j] * a[0];
        for (i = 1; i < (j + 1) / 2; i++) {t += (dchunk)a[j - i] * a[i]; }
        t += t; t += co;
        c[j] = (chunk)t & BMASK_B256_28;
        co = t >> BASEBITS_B256_28;
        j++;
        t = (dchunk)a[j] * a[0];
        for (i = 1; i < (j + 1) / 2; i++) {t += (dchunk)a[j - i] * a[i]; }
        t += t; t += co;
        t += (dchunk)a[j / 2] * a[j / 2];
        c[j] = (chunk)t & BMASK_B256_28;
        co = t >> BASEBITS_B256_28;
        j++;
    }

    for (j = NLEN_B256_28 - 1 + NLEN_B256_28 % 2; j < DNLEN_B256_28 - 3; )
    {
        t = (dchunk)a[NLEN_B256_28 - 1] * a[j - NLEN_B256_28 + 1];
        for (i = j - NLEN_B256_28 + 2; i < (j + 1) / 2; i++) {t += (dchunk)a[j - i] * a[i];  }
        t += t; t += co;
        c[j] = (chunk)t & BMASK_B256_28;
        co = t >> BASEBITS_B256_28;
        j++;
        t = (dchunk)a[NLEN_B256_28 - 1] * a[j - NLEN_B256_28 + 1];
        for (i = j - NLEN_B256_28 + 2; i < (j + 1) / 2; i++) {t += (dchunk)a[j - i] * a[i];  }
        t += t; t += co;
        t += (dchunk)a[j / 2] * a[j / 2];
        c[j] = (chunk)t & BMASK_B256_28;
        co = t >> BASEBITS_B256_28;
        j++;
    }

    t = (dchunk)a[NLEN_B256_28 - 2] * a[NLEN_B256_28 - 1];
    t += t; t += co;
    c[DNLEN_B256_28 - 3] = (chunk)t & BMASK_B256_28;
    co = t >> BASEBITS_B256_28;

    t = (dchunk)a[NLEN_B256_28 - 1] * a[NLEN_B256_28 - 1] + co;
    c[DNLEN_B256_28 - 2] = (chunk)t & BMASK_B256_28;
    co = t >> BASEBITS_B256_28;
    c[DNLEN_B256_28 - 1] = (chunk)co;


#endif

#else
    chunk carry;
    BIG_dzero(c);
    for (i = 0; i < NLEN_B256_28; i++)
    {
        carry = 0;
        for (j = i + 1; j < NLEN_B256_28; j++)
            carry = muladd(a[i], a[j], carry, &c[i + j]);
        c[NLEN_B256_28 + i] = carry;
    }

    for (i = 0; i < DNLEN_B256_28; i++) c[i] *= 2;

    for (i = 0; i < NLEN_B256_28; i++)
        c[2 * i + 1] += muladd(a[i], a[i], 0, &c[2 * i]);

    BIG_dnorm(c); 
#endif


#ifdef DEBUG_NORM
    c[DMPV_B256_28] = 1;
    c[DMNV_B256_28] = 0;
#endif

}

/* Montgomery reduction */
void B256_28::BIG_monty(BIG a, BIG md, chunk MC, DBIG d)
{
    int i, k;

#ifdef dchunk
    dchunk c,t,s;
    dchunk dd[NLEN_B256_28];
    chunk v[NLEN_B256_28];
#endif


#ifdef DEBUG_NORM
    if ((d[DMPV_B256_28] != 1 && d[DMPV_B256_28] != 0) || d[DMNV_B256_28] != 0) printf("Input to redc not normed\n");
#endif

#ifdef COMBA

#ifdef UNWOUND

#ifdef USE_KARATSUBA

    	t=d[0]; v[0]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[0]*md[0];  s=0; c=(t>>BASEBITS_B256_28);

	t=d[1]+c+s+(dchunk)v[0]*md[1]; v[1]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[1]*md[0];  dd[1]=(dchunk)v[1]*md[1]; s+=dd[1]; c=(t>>BASEBITS_B256_28); 
	t=d[2]+c+s+(dchunk)v[0]*md[2]; v[2]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[2]*md[0];  dd[2]=(dchunk)v[2]*md[2]; s+=dd[2]; c=(t>>BASEBITS_B256_28); 
	t=d[3]+c+s+(dchunk)v[0]*md[3]+(dchunk)(v[1]-v[2])*(md[2]-md[1]); v[3]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[3]*md[0];  dd[3]=(dchunk)v[3]*md[3]; s+=dd[3]; c=(t>>BASEBITS_B256_28); 
	t=d[4]+c+s+(dchunk)v[0]*md[4]+(dchunk)(v[1]-v[3])*(md[3]-md[1]); v[4]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[4]*md[0];  dd[4]=(dchunk)v[4]*md[4]; s+=dd[4]; c=(t>>BASEBITS_B256_28); 
	t=d[5]+c+s+(dchunk)v[0]*md[5]+(dchunk)(v[1]-v[4])*(md[4]-md[1])+(dchunk)(v[2]-v[3])*(md[3]-md[2]); v[5]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[5]*md[0];  dd[5]=(dchunk)v[5]*md[5]; s+=dd[5]; c=(t>>BASEBITS_B256_28); 
	t=d[6]+c+s+(dchunk)v[0]*md[6]+(dchunk)(v[1]-v[5])*(md[5]-md[1])+(dchunk)(v[2]-v[4])*(md[4]-md[2]); v[6]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[6]*md[0];  dd[6]=(dchunk)v[6]*md[6]; s+=dd[6]; c=(t>>BASEBITS_B256_28); 
	t=d[7]+c+s+(dchunk)v[0]*md[7]+(dchunk)(v[1]-v[6])*(md[6]-md[1])+(dchunk)(v[2]-v[5])*(md[5]-md[2])+(dchunk)(v[3]-v[4])*(md[4]-md[3]); v[7]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[7]*md[0];  dd[7]=(dchunk)v[7]*md[7]; s+=dd[7]; c=(t>>BASEBITS_B256_28); 
	t=d[8]+c+s+(dchunk)v[0]*md[8]+(dchunk)(v[1]-v[7])*(md[7]-md[1])+(dchunk)(v[2]-v[6])*(md[6]-md[2])+(dchunk)(v[3]-v[5])*(md[5]-md[3]); v[8]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[8]*md[0];  dd[8]=(dchunk)v[8]*md[8]; s+=dd[8]; c=(t>>BASEBITS_B256_28); 
	t=d[9]+c+s+(dchunk)v[0]*md[9]+(dchunk)(v[1]-v[8])*(md[8]-md[1])+(dchunk)(v[2]-v[7])*(md[7]-md[2])+(dchunk)(v[3]-v[6])*(md[6]-md[3])+(dchunk)(v[4]-v[5])*(md[5]-md[4]); v[9]=((chunk)t*MC)&BMASK_B256_28; t+=(dchunk)v[9]*md[0];  dd[9]=(dchunk)v[9]*md[9]; s+=dd[9]; c=(t>>BASEBITS_B256_28); 

	t=d[10]+c+s+(dchunk)(v[1]-v[9])*(md[9]-md[1])+(dchunk)(v[2]-v[8])*(md[8]-md[2])+(dchunk)(v[3]-v[7])*(md[7]-md[3])+(dchunk)(v[4]-v[6])*(md[6]-md[4]); a[0]=(chunk)t&BMASK_B256_28;  s-=dd[1]; c=(t>>BASEBITS_B256_28); 
	t=d[11]+c+s+(dchunk)(v[2]-v[9])*(md[9]-md[2])+(dchunk)(v[3]-v[8])*(md[8]-md[3])+(dchunk)(v[4]-v[7])*(md[7]-md[4])+(dchunk)(v[5]-v[6])*(md[6]-md[5]); a[1]=(chunk)t&BMASK_B256_28;  s-=dd[2]; c=(t>>BASEBITS_B256_28); 
	t=d[12]+c+s+(dchunk)(v[3]-v[9])*(md[9]-md[3])+(dchunk)(v[4]-v[8])*(md[8]-md[4])+(dchunk)(v[5]-v[7])*(md[7]-md[5]); a[2]=(chunk)t&BMASK_B256_28;  s-=dd[3]; c=(t>>BASEBITS_B256_28); 
	t=d[13]+c+s+(dchunk)(v[4]-v[9])*(md[9]-md[4])+(dchunk)(v[5]-v[8])*(md[8]-md[5])+(dchunk)(v[6]-v[7])*(md[7]-md[6]); a[3]=(chunk)t&BMASK_B256_28;  s-=dd[4]; c=(t>>BASEBITS_B256_28); 
	t=d[14]+c+s+(dchunk)(v[5]-v[9])*(md[9]-md[5])+(dchunk)(v[6]-v[8])*(md[8]-md[6]); a[4]=(chunk)t&BMASK_B256_28;  s-=dd[5]; c=(t>>BASEBITS_B256_28); 
	t=d[15]+c+s+(dchunk)(v[6]-v[9])*(md[9]-md[6])+(dchunk)(v[7]-v[8])*(md[8]-md[7]); a[5]=(chunk)t&BMASK_B256_28;  s-=dd[6]; c=(t>>BASEBITS_B256_28); 
	t=d[16]+c+s+(dchunk)(v[7]-v[9])*(md[9]-md[7]); a[6]=(chunk)t&BMASK_B256_28;  s-=dd[7]; c=(t>>BASEBITS_B256_28); 
	t=d[17]+c+s+(dchunk)(v[8]-v[9])*(md[9]-md[8]); a[7]=(chunk)t&BMASK_B256_28;  s-=dd[8]; c=(t>>BASEBITS_B256_28); 
	t=d[18]+c+s; a[8]=(chunk)t&BMASK_B256_28;  s-=dd[9]; c=(t>>BASEBITS_B256_28); 
	a[9]=d[19]+((chunk)c&BMASK_B256_28);


#else

    	t = d[0];
	v[0] = ((chunk)t * MC)&BMASK_B256_28;
	t += (dchunk)v[0] * md[0];
	t = (t >> BASEBITS_B256_28) + d[1];
	t += (dchunk)v[0] * md[1] ; v[1] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[1] * md[0]; t = (t >> BASEBITS_B256_28) + d[2];
	t += (dchunk)v[0] * md[2] + (dchunk)v[1]*md[1]; v[2] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[2] * md[0]; t = (t >> BASEBITS_B256_28) + d[3];
	t += (dchunk)v[0] * md[3] + (dchunk)v[1]*md[2]+ (dchunk)v[2]*md[1]; v[3] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[3] * md[0]; t = (t >> BASEBITS_B256_28) + d[4];
	t += (dchunk)v[0] * md[4] + (dchunk)v[1]*md[3]+ (dchunk)v[2]*md[2]+ (dchunk)v[3]*md[1]; v[4] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[4] * md[0]; t = (t >> BASEBITS_B256_28) + d[5];
	t += (dchunk)v[0] * md[5] + (dchunk)v[1]*md[4]+ (dchunk)v[2]*md[3]+ (dchunk)v[3]*md[2]+ (dchunk)v[4]*md[1]; v[5] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[5] * md[0]; t = (t >> BASEBITS_B256_28) + d[6];
	t += (dchunk)v[0] * md[6] + (dchunk)v[1]*md[5]+ (dchunk)v[2]*md[4]+ (dchunk)v[3]*md[3]+ (dchunk)v[4]*md[2]+ (dchunk)v[5]*md[1]; v[6] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[6] * md[0]; t = (t >> BASEBITS_B256_28) + d[7];
	t += (dchunk)v[0] * md[7] + (dchunk)v[1]*md[6]+ (dchunk)v[2]*md[5]+ (dchunk)v[3]*md[4]+ (dchunk)v[4]*md[3]+ (dchunk)v[5]*md[2]+ (dchunk)v[6]*md[1]; v[7] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[7] * md[0]; t = (t >> BASEBITS_B256_28) + d[8];
	t += (dchunk)v[0] * md[8] + (dchunk)v[1]*md[7]+ (dchunk)v[2]*md[6]+ (dchunk)v[3]*md[5]+ (dchunk)v[4]*md[4]+ (dchunk)v[5]*md[3]+ (dchunk)v[6]*md[2]+ (dchunk)v[7]*md[1]; v[8] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[8] * md[0]; t = (t >> BASEBITS_B256_28) + d[9];
	t += (dchunk)v[0] * md[9] + (dchunk)v[1]*md[8]+ (dchunk)v[2]*md[7]+ (dchunk)v[3]*md[6]+ (dchunk)v[4]*md[5]+ (dchunk)v[5]*md[4]+ (dchunk)v[6]*md[3]+ (dchunk)v[7]*md[2]+ (dchunk)v[8]*md[1]; v[9] = ((chunk)t * MC)&BMASK_B256_28; t += (dchunk)v[9] * md[0]; t = (t >> BASEBITS_B256_28) + d[10];
	t=t + (dchunk)v[1]*md[9] + (dchunk)v[2]*md[8] + (dchunk)v[3]*md[7] + (dchunk)v[4]*md[6] + (dchunk)v[5]*md[5] + (dchunk)v[6]*md[4] + (dchunk)v[7]*md[3] + (dchunk)v[8]*md[2] + (dchunk)v[9]*md[1] ; a[0] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[11];
	t=t + (dchunk)v[2]*md[9] + (dchunk)v[3]*md[8] + (dchunk)v[4]*md[7] + (dchunk)v[5]*md[6] + (dchunk)v[6]*md[5] + (dchunk)v[7]*md[4] + (dchunk)v[8]*md[3] + (dchunk)v[9]*md[2] ; a[1] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[12];
	t=t + (dchunk)v[3]*md[9] + (dchunk)v[4]*md[8] + (dchunk)v[5]*md[7] + (dchunk)v[6]*md[6] + (dchunk)v[7]*md[5] + (dchunk)v[8]*md[4] + (dchunk)v[9]*md[3] ; a[2] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[13];
	t=t + (dchunk)v[4]*md[9] + (dchunk)v[5]*md[8] + (dchunk)v[6]*md[7] + (dchunk)v[7]*md[6] + (dchunk)v[8]*md[5] + (dchunk)v[9]*md[4] ; a[3] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[14];
	t=t + (dchunk)v[5]*md[9] + (dchunk)v[6]*md[8] + (dchunk)v[7]*md[7] + (dchunk)v[8]*md[6] + (dchunk)v[9]*md[5] ; a[4] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[15];
	t=t + (dchunk)v[6]*md[9] + (dchunk)v[7]*md[8] + (dchunk)v[8]*md[7] + (dchunk)v[9]*md[6] ; a[5] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[16];
	t=t + (dchunk)v[7]*md[9] + (dchunk)v[8]*md[8] + (dchunk)v[9]*md[7] ; a[6] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[17];
	t=t + (dchunk)v[8]*md[9] + (dchunk)v[9]*md[8] ; a[7] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[18];
	t=t + (dchunk)v[9]*md[9] ; a[8] = (chunk)t & BMASK_B256_28; t = (t >> BASEBITS_B256_28) + d[19];
	a[9] = (chunk)t & BMASK_B256_28;


#endif

#else

#ifndef USE_KARATSUBA 
    t = d[0];
    v[0] = ((chunk)t * MC)&BMASK_B256_28;
    t += (dchunk)v[0] * md[0];
    t = (t >> BASEBITS_B256_28) + d[1];
   
    for (i = 1; i < NLEN_B256_28; i++)
    {
        k=1;
        t += (dchunk)v[0] * md[i];
        while (k<i) {t += (dchunk)v[k]*md[i-k]; k++;}
        v[i] = ((chunk)t * MC)&BMASK_B256_28;
        t += (dchunk)v[i] * md[0];
        t = (t >> BASEBITS_B256_28) + d[i + 1];
    }
    for (i = NLEN_B256_28; i < 2 * NLEN_B256_28 - 1; i++)
    {
        k=i-(NLEN_B256_28-1);
        while (k<=NLEN_B256_28-1) {t += (dchunk)v[k]*md[i-k]; k++;}
        a[i - NLEN_B256_28] = (chunk)t & BMASK_B256_28;
        t = (t >> BASEBITS_B256_28) + d[i + 1];
    }
    a[NLEN_B256_28 - 1] = (chunk)t & BMASK_B256_28;
#else

    t = d[0];
    v[0] = ((chunk)t * MC)&BMASK_B256_28;
    t += (dchunk)v[0] * md[0];
    t = (t >> BASEBITS_B256_28) + d[1];
    s = 0;

    for (k = 1; k < NLEN_B256_28; k++)
    {
        t = t + s + (dchunk)v[0] * md[k];

        for (i=1+k/2;i<k;i++) t += (dchunk)(v[k - i] - v[i]) * (md[i] - md[k - i]);
        v[k] = ((chunk)t * MC)&BMASK_B256_28;
        t += (dchunk)v[k] * md[0];
        t = (t >> BASEBITS_B256_28) + d[k + 1];
        dd[k] = (dchunk)v[k] * md[k];
        s += dd[k];
    }
    for (k = NLEN_B256_28; k < 2 * NLEN_B256_28 - 1; k++)
    {
        t = t + s;
        for (i=1+k/2;i<NLEN_B256_28;i++) t += (dchunk)(v[k - i] - v[i]) * (md[i] - md[k - i]);
        a[k - NLEN_B256_28] = (chunk)t & BMASK_B256_28;
        t = (t >> BASEBITS_B256_28) + d[k + 1];
        s -= dd[k - NLEN_B256_28 + 1];
    }
    a[NLEN_B256_28 - 1] = (chunk)t & BMASK_B256_28;
#endif

#endif



#else
    int j;
    chunk m, carry;
    for (i = 0; i < NLEN_B256_28; i++)
    {
        if (MC == -1) m = (-d[i])&BMASK_B256_28;
        else
        {
            if (MC == 1) m = d[i];
            else m = (MC * d[i])&BMASK_B256_28;
        }
        carry = 0;
        for (j = 0; j < NLEN_B256_28; j++)
            carry = muladd(m, md[j], carry, &d[i + j]);
        d[NLEN_B256_28 + i] += carry;
    }
    BIG_sducopy(a, d);
    BIG_norm(a);

#endif

#ifdef DEBUG_NORM
    a[MPV_B256_28] = 1;  a[MNV_B256_28] = 0;
#endif
}

/* General shift left of a by n bits */
/* a MUST be normalised */
/* SU= 32 */
void B256_28::BIG_shl(BIG a, int k)
{
    int i;
    int n = k % BASEBITS_B256_28;
    int m = k / BASEBITS_B256_28;

    a[NLEN_B256_28 - 1] = ((a[NLEN_B256_28 - 1 - m] << n));
    if (NLEN_B256_28 >= m + 2) a[NLEN_B256_28 - 1] |= (a[NLEN_B256_28 - m - 2] >> (BASEBITS_B256_28 - n));

    for (i = NLEN_B256_28 - 2; i > m; i--)
        a[i] = ((a[i - m] << n)&BMASK_B256_28) | (a[i - m - 1] >> (BASEBITS_B256_28 - n));
    a[m] = (a[0] << n)&BMASK_B256_28;
    for (i = 0; i < m; i++) a[i] = 0;

}

/* Fast shift left of a by n bits, where n less than a word, Return excess (but store it as well) */
/* a MUST be normalised */
/* SU= 16 */
int B256_28::BIG_fshl(BIG a, int n)
{
    int i;

    a[NLEN_B256_28 - 1] = ((a[NLEN_B256_28 - 1] << n)) | (a[NLEN_B256_28 - 2] >> (BASEBITS_B256_28 - n)); /* top word not masked */
    for (i = NLEN_B256_28 - 2; i > 0; i--)
        a[i] = ((a[i] << n)&BMASK_B256_28) | (a[i - 1] >> (BASEBITS_B256_28 - n));
    a[0] = (a[0] << n)&BMASK_B256_28;

    return (int)(a[NLEN_B256_28 - 1] >> ((8 * MODBYTES_B256_28) % BASEBITS_B256_28)); /* return excess - only used in ff.c */
}

/* double length left shift of a by k bits - k can be > BASEBITS_B256_28 , a MUST be normalised */
/* SU= 32 */
void B256_28::BIG_dshl(DBIG a, int k)
{
    int i;
    int n = k % BASEBITS_B256_28;
    int m = k / BASEBITS_B256_28;

    a[DNLEN_B256_28 - 1] = ((a[DNLEN_B256_28 - 1 - m] << n)) | (a[DNLEN_B256_28 - m - 2] >> (BASEBITS_B256_28 - n));

    for (i = DNLEN_B256_28 - 2; i > m; i--)
        a[i] = ((a[i - m] << n)&BMASK_B256_28) | (a[i - m - 1] >> (BASEBITS_B256_28 - n));
    a[m] = (a[0] << n)&BMASK_B256_28;
    for (i = 0; i < m; i++) a[i] = 0;

}

/* General shift rightof a by k bits */
/* a MUST be normalised */
/* SU= 32 */
void B256_28::BIG_shr(BIG a, int k)
{
    int i;
    int n = k % BASEBITS_B256_28;
    int m = k / BASEBITS_B256_28;
    for (i = 0; i < NLEN_B256_28 - m - 1; i++)
        a[i] = (a[m + i] >> n) | ((a[m + i + 1] << (BASEBITS_B256_28 - n))&BMASK_B256_28);
    if (NLEN_B256_28 > m)  a[NLEN_B256_28 - m - 1] = a[NLEN_B256_28 - 1] >> n;
    for (i = NLEN_B256_28 - m; i < NLEN_B256_28; i++) a[i] = 0;

}

/* Fast combined shift, subtract and norm. Return sign of result */
int B256_28::BIG_ssn(BIG r, BIG a, BIG m)
{
    int i, n = NLEN_B256_28 - 1;
    chunk carry;
    m[0] = (m[0] >> 1) | ((m[1] << (BASEBITS_B256_28 - 1))&BMASK_B256_28);
    r[0] = a[0] - m[0];
    carry = r[0] >> BASEBITS_B256_28;
    r[0] &= BMASK_B256_28;

    for (i = 1; i < n; i++)
    {
        m[i] = (m[i] >> 1) | ((m[i + 1] << (BASEBITS_B256_28 - 1))&BMASK_B256_28);
        r[i] = a[i] - m[i] + carry;
        carry = r[i] >> BASEBITS_B256_28;
        r[i] &= BMASK_B256_28;
    }

    m[n] >>= 1;
    r[n] = a[n] - m[n] + carry;
#ifdef DEBUG_NORM
    r[MPV_B256_28] = 1; r[MNV_B256_28] = 0;
#endif
    return ((r[n] >> (CHUNK - 1)) & 1);
}

/* Faster shift right of a by k bits. Return shifted out part */
/* a MUST be normalised */
/* SU= 16 */
int B256_28::BIG_fshr(BIG a, int k)
{
    int i;
    chunk r = a[0] & (((chunk)1 << k) - 1); /* shifted out part */
    for (i = 0; i < NLEN_B256_28 - 1; i++)
        a[i] = (a[i] >> k) | ((a[i + 1] << (BASEBITS_B256_28 - k))&BMASK_B256_28);
    a[NLEN_B256_28 - 1] = a[NLEN_B256_28 - 1] >> k;
    return (int)r;
}

/* double length right shift of a by k bits - can be > BASEBITS_B256_28 */
/* SU= 32 */
void B256_28::BIG_dshr(DBIG a, int k)
{
    int i;
    int n = k % BASEBITS_B256_28;
    int m = k / BASEBITS_B256_28;
    for (i = 0; i < DNLEN_B256_28 - m - 1; i++)
        a[i] = (a[m + i] >> n) | ((a[m + i + 1] << (BASEBITS_B256_28 - n))&BMASK_B256_28);
    a[DNLEN_B256_28 - m - 1] = a[DNLEN_B256_28 - 1] >> n;
    for (i = DNLEN_B256_28 - m; i < DNLEN_B256_28; i++ ) a[i] = 0;
}

/* Split DBIG d into two BIGs t|b. Split happens at n bits, where n falls into NLEN_B256_28 word */
/* d MUST be normalised */
/* SU= 24 */
chunk B256_28::BIG_split(BIG t, BIG b, DBIG d, int n)
{
    int i;
    chunk nw, carry = 0;
    int m = n % BASEBITS_B256_28;

    if (m == 0)
    {
        for (i = 0; i < NLEN_B256_28; i++) b[i] = d[i];
        if (t != b)
        {
            for (i = NLEN_B256_28; i < 2 * NLEN_B256_28; i++) t[i - NLEN_B256_28] = d[i];
            carry = t[NLEN_B256_28 - 1] >> BASEBITS_B256_28;
            t[NLEN_B256_28 - 1] = t[NLEN_B256_28 - 1] & BMASK_B256_28; /* top word normalized */
        }
        return carry;
    }

    for (i = 0; i < NLEN_B256_28 - 1; i++) b[i] = d[i];

    b[NLEN_B256_28 - 1] = d[NLEN_B256_28 - 1] & (((chunk)1 << m) - 1);

    if (t != b)
    {
        carry = (d[DNLEN_B256_28 - 1] << (BASEBITS_B256_28 - m));
        for (i = DNLEN_B256_28 - 2; i >= NLEN_B256_28 - 1; i--)
        {
            nw = (d[i] >> m) | carry;
            carry = (d[i] << (BASEBITS_B256_28 - m))&BMASK_B256_28;
            t[i - NLEN_B256_28 + 1] = nw;
        }
    }
#ifdef DEBUG_NORM
    t[MPV_B256_28] = 1; t[MNV_B256_28] = 0;
    b[MPV_B256_28] = 1; b[MNV_B256_28] = 0;
#endif
    return carry;
}

/* you gotta keep the sign of carry! Look - no branching! */
/* Note that sign bit is needed to disambiguate between +ve and -ve values */
/* normalise BIG - force all digits < 2^BASEBITS_B256_28 */
chunk B256_28::BIG_norm(BIG a)
{
    int i;
    chunk d, carry = 0;
    for (i = 0; i < NLEN_B256_28 - 1; i++)
    {
        d = a[i] + carry;
        a[i] = d & BMASK_B256_28;
        carry = d >> BASEBITS_B256_28;
    }
    a[NLEN_B256_28 - 1] = (a[NLEN_B256_28 - 1] + carry);

#ifdef DEBUG_NORM
    a[MPV_B256_28] = 1; a[MNV_B256_28] = 0;
#endif
    return (a[NLEN_B256_28 - 1] >> ((8 * MODBYTES_B256_28) % BASEBITS_B256_28)); /* only used in ff.c */
}

void B256_28::BIG_dnorm(DBIG a)
{
    int i;
    chunk d, carry = 0;
    for (i = 0; i < DNLEN_B256_28 - 1; i++)
    {
        d = a[i] + carry;
        a[i] = d & BMASK_B256_28;
        carry = d >> BASEBITS_B256_28;
    }
    a[DNLEN_B256_28 - 1] = (a[DNLEN_B256_28 - 1] + carry);
#ifdef DEBUG_NORM
    a[DMPV_B256_28] = 1; a[DMNV_B256_28] = 0;
#endif
}

/* Compare a and b. Return 1 for a>b, -1 for a<b, 0 for a==b */
/* a and b MUST be normalised before call */
/* sodium constant time implementation */

int B256_28::BIG_comp(BIG a, BIG b)
{
    int i;
    chunk gt=0; chunk eq=1;
    for (i = NLEN_B256_28-1; i>=0; i--)
    {
        gt |= ((b[i]-a[i]) >> BASEBITS_B256_28) & eq;
        eq &= ((b[i]^a[i])-1) >> BASEBITS_B256_28;
    }
    return (int)(gt+gt+eq-1);
}

int B256_28::BIG_dcomp(DBIG a, DBIG b)
{
    int i;
    chunk gt=0; chunk eq=1;
    for (i = DNLEN_B256_28-1; i>=0; i--)
    {
        gt |= ((b[i]-a[i]) >> BASEBITS_B256_28) & eq;
        eq &= ((b[i]^a[i])-1) >> BASEBITS_B256_28;
    }
    return (int)(gt+gt+eq-1);
}

/* return number of bits in a */
/* SU= 8 */
int B256_28::BIG_nbits(BIG a)
{
    int bts, k = NLEN_B256_28 - 1;
    BIG t;
    chunk c;
    BIG_copy(t, a);
    BIG_norm(t);
    while (k >= 0 && t[k] == 0) k--;
    if (k < 0) return 0;
    bts = BASEBITS_B256_28 * k;
    c = t[k];
    while (c != 0)
    {
        c /= 2;
        bts++;
    }
    return bts;
}

/* SU= 8, Calculate number of bits in a DBIG - output normalised */
int B256_28::BIG_dnbits(DBIG a)
{
    int bts, k = DNLEN_B256_28 - 1;
    DBIG t;
    chunk c;
    BIG_dcopy(t, a);
    BIG_dnorm(t);
    while (k >= 0 && t[k] == 0) k--;
    if (k < 0) return 0;
    bts = BASEBITS_B256_28 * k;
    c = t[k];
    while (c != 0)
    {
        c /= 2;
        bts++;
    }
    return bts;
}


/* Set b=b mod c */
/* SU= 16 */
void B256_28::BIG_mod(BIG b, BIG c1)
{
    int k = 0;
    BIG r; /**/
    BIG c;
    BIG_copy(c, c1);

    BIG_norm(b);
    if (BIG_comp(b, c) < 0)
        return;
    do
    {
        BIG_fshl(c, 1);
        k++;
    }
    while (BIG_comp(b, c) >= 0);

    while (k > 0)
    {
        BIG_fshr(c, 1);

// constant time...
        BIG_sub(r, b, c);
        BIG_norm(r);
        BIG_cmove(b, r, 1 - ((r[NLEN_B256_28 - 1] >> (CHUNK - 1)) & 1));
        k--;
    }
}

/* Set a=b mod c, b is destroyed. Slow but rarely used. */
/* SU= 96 */
void B256_28::BIG_dmod(BIG a, DBIG b, BIG c)
{
    int k = 0;
    DBIG m, r;
    BIG_dnorm(b);
    BIG_dscopy(m, c);

    if (BIG_dcomp(b, m) < 0)
    {
        BIG_sdcopy(a, b);
        return;
    }

    do
    {
        BIG_dshl(m, 1);
        k++;
    }
    while (BIG_dcomp(b, m) >= 0);

    while (k > 0)
    {
        BIG_dshr(m, 1);
// constant time...
        BIG_dsub(r, b, m);
        BIG_dnorm(r);
        BIG_dcmove(b, r, 1 - ((r[DNLEN_B256_28 - 1] >> (CHUNK - 1)) & 1));

        k--;
    }
    BIG_sdcopy(a, b);
}

/* Set a=b/c,  b is destroyed. Slow but rarely used. */
/* SU= 136 */

void B256_28::BIG_ddiv(BIG a, DBIG b, BIG c)
{
    int d, k = 0;
    DBIG m, dr;
    BIG e, r;
    BIG_dnorm(b);
    BIG_dscopy(m, c);

    BIG_zero(a);
    BIG_zero(e);
    BIG_inc(e, 1);

    while (BIG_dcomp(b, m) >= 0)
    {
        BIG_fshl(e, 1);
        BIG_dshl(m, 1);
        k++;
    }

    while (k > 0)
    {
        BIG_dshr(m, 1);
        BIG_fshr(e, 1);

        BIG_dsub(dr, b, m);
        BIG_dnorm(dr);
        d = 1 - ((dr[DNLEN_B256_28 - 1] >> (CHUNK - 1)) & 1);
        BIG_dcmove(b, dr, d);

        BIG_add(r, a, e);
        BIG_norm(r);
        BIG_cmove(a, r, d);

        k--;
    }
}

/* SU= 136 */

void B256_28::BIG_sdiv(BIG a, BIG c)
{
    int d, k = 0;
    BIG m, e, b, r;
    BIG_norm(a);
    BIG_copy(b, a);
    BIG_copy(m, c);

    BIG_zero(a);
    BIG_zero(e);
    BIG_inc(e, 1);

    while (BIG_comp(b, m) >= 0)
    {
        BIG_fshl(e, 1);
        BIG_fshl(m, 1);
        k++;
    }

    while (k > 0)
    {
        BIG_fshr(m, 1);
        BIG_fshr(e, 1);

        BIG_sub(r, b, m);
        BIG_norm(r);
        d = 1 - ((r[NLEN_B256_28 - 1] >> (CHUNK - 1)) & 1);
        BIG_cmove(b, r, d);

        BIG_add(r, a, e);
        BIG_norm(r);
        BIG_cmove(a, r, d);
        k--;
    }
}

/* return LSB of a */
int B256_28::BIG_parity(BIG a)
{
    return a[0] % 2;
}

/* return n-th bit of a */
/* SU= 16 */
int B256_28::BIG_bit(BIG a, int n)
{
    if (a[n / BASEBITS_B256_28] & ((chunk)1 << (n % BASEBITS_B256_28))) return 1;
    else return 0;
}

/* return last n bits of a, where n is small < BASEBITS_B256_28 */
/* SU= 16 */
int B256_28::BIG_lastbits(BIG a, int n)
{
    int msk = (1 << n) - 1;
    BIG_norm(a);
    return ((int)a[0])&msk;
}

/* get 8*MODBYTES_B256_28 size random number */
void B256_28::BIG_random(BIG m, csprng *rng)
{
    int i, b, j = 0, r = 0;
    int len = 8 * MODBYTES_B256_28;

    BIG_zero(m);
    /* generate random BIG */
    for (i = 0; i < len; i++)
    {
        if (j == 0) r = RAND_byte(rng);
        else r >>= 1;
        b = r & 1;
        BIG_shl(m, 1);
        m[0] += b;
        j++;
        j &= 7;
    }

#ifdef DEBUG_NORM
    m[MPV_B256_28] = 1; m[MNV_B256_28] = 0;
#endif
}

/* get random BIG from rng, modulo q. Done one bit at a time, so its portable */

void B256_28::BIG_randomnum(BIG m, BIG q, csprng *rng)
{
    int i, b, j = 0, r = 0;
    DBIG d;
    BIG_dzero(d);
    /* generate random DBIG */
    for (i = 0; i < 2 * BIG_nbits(q); i++)
    {
        if (j == 0) r = RAND_byte(rng);
        else r >>= 1;
        b = r & 1;
        BIG_dshl(d, 1);
        d[0] += b;
        j++;
        j &= 7;
    }
    /* reduce modulo a BIG. Removes bias */
    BIG_dmod(m, d, q);
#ifdef DEBUG_NORM
    m[MPV_B256_28] = 1; m[MNV_B256_28] = 0;
#endif
}

/* create randum BIG less than r and less than trunc bits */
void B256_28::BIG_randtrunc(BIG s, BIG r, int trunc, csprng *rng)
{
    BIG_randomnum(s, r, rng);
    if (BIG_nbits(r) > trunc)
        BIG_mod2m(s, trunc);
}

/* Set r=a*b mod m */
/* SU= 96 */
void B256_28::BIG_modmul(BIG r, BIG a1, BIG b1, BIG m)
{
    DBIG d;
    BIG a, b;
    BIG_copy(a, a1);
    BIG_copy(b, b1);
    BIG_mod(a, m);
    BIG_mod(b, m);

    BIG_mul(d, a, b);
    BIG_dmod(r, d, m);
}

/* Set a=a*a mod m */
/* SU= 88 */
void B256_28::BIG_modsqr(BIG r, BIG a1, BIG m)
{
    DBIG d;
    BIG a;
    BIG_copy(a, a1);
    BIG_mod(a, m);
    BIG_sqr(d, a);
    BIG_dmod(r, d, m);
}

/* Set r=-a mod m */
/* SU= 16 */
void B256_28::BIG_modneg(BIG r, BIG a1, BIG m)
{
    BIG a;
    BIG_copy(a, a1);
    BIG_mod(a, m);
    BIG_sub(r, m, a);
    BIG_mod(r, m);
}

/* Set r=a+b mod m */
void B256_28::BIG_modadd(BIG r, BIG a1, BIG b1, BIG m)
{
    BIG a, b;
    BIG_copy(a, a1);
    BIG_copy(b, b1);
    BIG_mod(a, m);
    BIG_mod(b, m);
    BIG_add(r,a,b); BIG_norm(r);
    BIG_mod(r,m);
}

/* Set a=a/b mod m */
/* SU= 136 */
void B256_28::BIG_moddiv(BIG r, BIG a1, BIG b1, BIG m)
{
    DBIG d;
    BIG z;
    BIG a, b;
    BIG_copy(a, a1);
    BIG_copy(b, b1);
    BIG_mod(a, m);
    BIG_invmodp(z, b, m);

    BIG_mul(d, a, z);
    BIG_dmod(r, d, m);
}

/* Get jacobi Symbol (a/p). Returns 0, 1 or -1 */
/* SU= 216 */
int B256_28::BIG_jacobi(BIG a, BIG p)
{
    int n8, k, m = 0;
    BIG t, x, n, zilch, one;
    BIG_one(one);
    BIG_zero(zilch);
    if (BIG_parity(p) == 0 || BIG_comp(a, zilch) == 0 || BIG_comp(p, one) <= 0) return 0;
    BIG_norm(a);
    BIG_copy(x, a);
    BIG_copy(n, p);
    BIG_mod(x, p);

    while (BIG_comp(n, one) > 0)
    {
        if (BIG_comp(x, zilch) == 0) return 0;
        n8 = BIG_lastbits(n, 3);
        k = 0;
        while (BIG_parity(x) == 0)
        {
            k++;
            BIG_shr(x, 1);
        }
        if (k % 2 == 1) m += (n8 * n8 - 1) / 8;
        m += (n8 - 1) * (BIG_lastbits(x, 2) - 1) / 4;
        BIG_copy(t, n);

        BIG_mod(t, x);
        BIG_copy(n, x);
        BIG_copy(x, t);
        m %= 2;

    }
    if (m == 0) return 1;
    else return -1;
}

/*

int B256_28::step1(BIG u,BIG x,BIG p)
{
    int k=0;
    BIG t;
    while (BIG_bit(u,k)==0)
    {
        BIG_add(t,x,p);
        BIG_cmove(x,t,BIG_parity(x));
        BIG_norm(x);
        BIG_fshr(x,1);
        k++;
    }
    return k;
}

void B256_28::step2(BIG xf,BIG xs,BIG p)
{
    BIG t;
    BIG_add(t,xf,p);
    BIG_cmove(xf,t,(BIG_comp(xf,xs)>>1)&1); // move if x1<x2 
    BIG_sub(xf,xf,xs);
    BIG_norm(xf);
}

*/

/* Set r=1/a mod p. Binary method */
void B256_28::BIG_invmodp(BIG r, BIG a, BIG p)
{
    BIG u, v, x1, x2, t, one;
    int par,s;

    BIG_mod(a, p);
    if (BIG_iszilch(a))
    {
        BIG_zero(r);
        return;
    }

    BIG_copy(u, a);
    BIG_copy(v, p);
    BIG_one(one);
    BIG_copy(x1, one);
    BIG_zero(x2);

    while (BIG_comp(u, one) != 0 && BIG_comp(v, one) != 0)
    {
        while (BIG_parity(u) == 0)
        {
            BIG_fshr(u, 1);
            BIG_add(t,x1,p);
            BIG_cmove(x1,t,BIG_parity(x1));
            BIG_norm(x1);
            BIG_fshr(x1,1);
        }
        while (BIG_parity(v) == 0)
        {
            BIG_fshr(v, 1);
            BIG_add(t,x2,p);
            BIG_cmove(x2,t,BIG_parity(x2));
            BIG_norm(x2);
            BIG_fshr(x2,1);
        } 
        if (BIG_comp(u, v) >= 0) 
        {
            BIG_sub(u, u, v);
            BIG_norm(u);
            BIG_add(t,x1,p);
            BIG_cmove(x1,t,(BIG_comp(x1,x2)>>1)&1); // move if x1<x2 
            BIG_sub(x1,x1,x2);
            BIG_norm(x1);
        }
        else
        {
            BIG_sub(v, v, u);
            BIG_norm(v);
            BIG_add(t,x2,p);
            BIG_cmove(x2,t,(BIG_comp(x2,x1)>>1)&1); // move if x2<x1 
            BIG_sub(x2,x2,x1);
            BIG_norm(x2);
        }
    }
    BIG_copy(r,x1);
    BIG_cmove(r,x2,BIG_comp(u,one)&1);
}


/* set x = x mod 2^m */
void B256_28::BIG_mod2m(BIG x, int m)
{
    int i, wd, bt;
    chunk msk;
    BIG_norm(x);

    wd = m / BASEBITS_B256_28;
    bt = m % BASEBITS_B256_28;
    msk = ((chunk)1 << bt) - 1;
    x[wd] &= msk;
    for (i = wd + 1; i < NLEN_B256_28; i++) x[i] = 0;
}

// new
/* Convert to DBIG number from byte array of given length */
void B256_28::BIG_dfromBytesLen(DBIG a, char *b, int s)
{
    int i, len = s;
    BIG_dzero(a);

    for (i = 0; i < len; i++)
    {
        BIG_dshl(a, 8);
        a[0] += (int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[DMPV_B256_28] = 1; a[DMNV_B256_28] = 0;
#endif
}
