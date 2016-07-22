#ifndef MESSAGE_H
#define MESSAGE_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>

using namespace std;

class RoguePriMsg 
{
    friend class issuer;
    friend class verifier;

public:
    mpz_class get_f0() const { return _f0; };
    mpz_class get_f1() const { return _f1; };

private:
    RoguePriMsg(mpz_class f0 = 0, mpz_class f1 = 0)
        : _f0(f0), _f1(f1) {}
    ~RoguePriMsg() {}

    // data member
    mpz_class   _f0;
    mpz_class   _f1;
};

class JoinSMsg 
{
    friend class TPM;

public:
    JoinSMsg(string c = "", string nt = "", mpz_class f0 = 0, mpz_class f1 = 0, mpz_class v = 0)
        : _c(c), _nt(nt), _f0(f0), _f1(f1), _v(v) { }
    ~JoinSMsg() { }

    string get_c() const { return _c; };
    string get_nt() const { return _nt; };
    mpz_class get_f0() const { return _f0; };
    mpz_class get_f1() const { return _f1; };
    mpz_class get_v() const { return _v; };

private:
    // data member
    string      _c;
    string      _nt; 
    mpz_class   _f0;
    mpz_class   _f1;
    mpz_class   _v;
};

class JoinSgntrA
{
    friend class Issuer;

public:
    JoinSgntrA(string c = "", mpz_class se = 0, mpz_class a = 0, mpz_class e = 0, mpz_class v = 0)
        : _c1(c), _se(se), _A(a), _e(e), _v2(v) { }
    ~JoinSgntrA() { }

    string get_c1() const { return _c1; };
    mpz_class get_se() const { return _se; };
    mpz_class get_A() const { return _A; };
    mpz_class get_e() const { return _e; };
    mpz_class get_v2() const { return _v2; };

private:
    // data member
    string      _c1;
    mpz_class   _se; 
    mpz_class   _A;
    mpz_class   _e;
    mpz_class   _v2;
};

#endif // MESSAGE_H
