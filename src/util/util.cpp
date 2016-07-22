#include <iostream>
#include <cmath>
#include <gmp.h>
#include <gmpxx.h>
#include "sha1.h"
#include "util.h"

using namespace std;

SHA1 _hash;
//SHA hashGM;

gmp_randclass myRNG(gmp_randinit_default);

/*
Initialize the RNG (only need to initialize 1 time!)
*/
void initRNG ()
{
    myRNG.seed(time(NULL));
}


/*
Get exactly n-bit-length random number
*/
mpz_class nBitsGen(size_t n)
{
    mpz_class temp;
    if(n<=1024) temp=pow(2,n-1);
    else mpz_ui_pow_ui(temp.get_mpz_t(),2,n-1);

    return temp+myRNG.get_z_bits(n-1);
};

/*
Get exactly n-bit-length random prime
(need to be improve since the probability not uniform)
*/
mpz_class nBitsPrimeGen(size_t n)
{

    mpz_class cmp;
    mpz_class temp;
    mpz_class prime;
    if(n<=1024) cmp=pow(2,n-1);
    else mpz_ui_pow_ui(cmp.get_mpz_t(),2,n-1);

    //check range
    do{
        temp=nBitsGen(n);
        mpz_nextprime(prime.get_mpz_t(),temp.get_mpz_t());
    }while(prime<cmp||(mpz_class)prime>2*cmp);

    return prime;
};

/*
Get exactly n-bit-length random safe prime
*/
mpz_class nBitsSafePrimeGen(size_t n)
{

    mpz_class cmp=pow(2,n-1);
    mpz_class temp;
    mpz_class prime=nBitsPrimeGen(n);
    mpz_class prm;
    //check range
    while(prime<cmp||(mpz_class)prime>2*cmp||mpz_probab_prime_p(prm.get_mpz_t(),25)==0){
        //in case of larger than the range
        if(prime>2*cmp) prime=nBitsPrimeGen(n);

        temp=prime;
        mpz_nextprime(prime.get_mpz_t(),temp.get_mpz_t());
        prm=(prime-1)/2;
    }
    return prime;
}

/*
Get a random generator of Quadatic Residue module n=pq
*/
mpz_class getQRGen (mpz_class p, mpz_class q)
{
/*
//find base of Z/nZ~Z/pZ*Z/qZ
mpz_class pGen,qGen,pTemp,qTemp,pPwr,qPwr,ret,n;
n=p*q;
pTemp=myRNG.get_z_range(p-1);
qTemp=myRNG.get_z_range(q-1);

//do{
mpz_nextprime(pGen.get_mpz_t(),pTemp.get_mpz_t());
//}while(pGen>p);

//do{
mpz_nextprime(qGen.get_mpz_t(),qTemp.get_mpz_t());
//}while(qGen>q);

//find power of Z/pZ, Z/qZ
pTemp=myRNG.get_z_range((p-1)/2);
qTemp=myRNG.get_z_range((q-1)/2);

do{
mpz_nextprime(pPwr.get_mpz_t(),pTemp.get_mpz_t());
}while(pPwr>(p-1)/2);

do{
mpz_nextprime(qPwr.get_mpz_t(),qTemp.get_mpz_t());
}while(qPwr>(q-1)/2);

mpz_powm(pTemp.get_mpz_t(),pGen.get_mpz_t(),pPwr.get_mpz_t(),n.get_mpz_t());
mpz_powm(qTemp.get_mpz_t(),qGen.get_mpz_t(),qPwr.get_mpz_t(),n.get_mpz_t());

pGen=pTemp*qTemp;
mpz_mod(ret.get_mpz_t(),pGen.get_mpz_t(),n.get_mpz_t());
return ret;
*/
    mpz_class pGen,qGen,ret,temp,n;
    do{
      pGen=myRNG.get_z_range(p-1);
    }while(pGen==1||pGen==p-1);
    do{ 
    qGen=myRNG.get_z_range(q-1);
    }while(qGen==1||qGen==q-1);
    pGen*=pGen;
    qGen*=qGen;
    temp=pGen*qGen;
    n=p*q;
    mpz_mod(ret.get_mpz_t(),temp.get_mpz_t(),n.get_mpz_t());
    return ret;

}

mpz_class directJoin(mpz_class num1, mpz_class num2)
{
string s=num1.get_str(16)+num2.get_str(16);
return myStr2Int(s,16);
}

// Check whether target is in the range of 0 ~ (2 ^ power - 1)
bool
isInCorrectRange(mpz_class target, int power)
{
    mpz_class cmp;
    if (power <= 1024) cmp = pow(2, power);
    else mpz_ui_pow_ui(cmp.get_mpz_t(), 2, power);
    if (target < 0 || target > cmp - 1) return false;
    else return true;
}
