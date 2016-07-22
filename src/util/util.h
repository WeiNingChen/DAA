#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <string>
#include <gmp.h>
#include <gmpxx.h>
#include "sha1.h"

using namespace std;

//myRNG

extern gmp_randclass myRNG;
extern void initRNG();

// utility function
extern mpz_class nBitsGen(size_t n);
extern mpz_class nBitsPrimeGen(size_t n);
extern mpz_class nBitsSafePrimeGen(size_t n);
extern mpz_class getQRGen(mpz_class p, mpz_class q);
extern mpz_class directJoin(mpz_class,mpz_class);
extern bool isInCorrectRange(mpz_class target, int power);

// hash function
extern SHA1 _hash;
//SHA hashGM;

// In myString.cpp
extern mpz_class myStr2Int(const string& str, const int& base);
extern string myInt2Str(int num, const int& base);

#endif
