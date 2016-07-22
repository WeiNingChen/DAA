#ifndef TPM_H
#define TPM_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <map>
#include <vector>
#include "scrtPrmt.h"
#include "issuer.h"
#include "host.h"
#include "message.h"
// issuer.h
class Issuer;
class IsrKey;

// tpm.h
class TPM;

// host.h
class Host;
class PriMsgSgntr;
class VerSignature;

// verifier.h
class Verifier;

using namespace std;

class PriMsg 
{
    friend class TPM;

    PriMsg(mpz_class f0 = 0, mpz_class f1 = 0, mpz_class v = 0)
        : _f0(f0), _f1(f1), _v(v) {}
    ~PriMsg() {}

    void setV(mpz_class v) { _v = v; }

    // data member
    mpz_class   _f0;
    mpz_class   _f1;
    mpz_class   _v;
};

class TPM_key
{
    friend class TPM;

public:
    mpz_class get_n() { return 0; }
    mpz_class get_e() { return 0; }

private:
    mpz_class p, q;
};

/*
class TPM_EK : public TPM_key
{
};
*/

/*
class TPM_AIK : public TPM_key
{
};
*/

class TPM 
{
    friend class JoinProtocol;

public:
    TPM() {}
    TPM(Host* h) : _cnt(0), _host(h), _issuer(NULL) {
        int seed = *(reinterpret_cast<int*>(h));
        _daaSeed = _hash(myInt2Str(seed, 16));
    }
    ~TPM() {}

    PriMsg* joinGetPriMsg() const { return _priMsgs.back(); }

    //for signing protocol
    Issuer* getIssuer() const { return _issuer; } 
    //to create verSignature
    bool	gen_N_v(VerSignature*, PriMsgSgntr*);
    bool	gen_n_t(VerSignature*, PriMsgSgntr*);
    //to create sigProof
    bool	gen_random(VerSignature*, PriMsgSgntr*);
    bool	gen_c(VerSignature*, Verifier*, mpz_class);
    bool	gen_sigProof(VerSignature*, PriMsgSgntr* );
    bool	reset();

    mpz_class	get_$T_1_t() const { return _memory[3]; }
    mpz_class	get_$r_f() const { return _memory[4]; }	
    mpz_class	get_$N_v() const { return _memory[5]; }

private:
    string          _daaSeed;  // 
    size_t          _cnt;      // 
    vector<PriMsg*> _priMsgs;

    Host*	        _host;
    Issuer*         _issuer;

    mutable vector<mpz_class> _memory;
    // for Join Protocol : [0] = stigma
    // for Signing Protocol

    // for Join Protocol
    bool joinCheckStigma(const mpz_class& stigma, const IsrKey&) const;
    void joinCrtPriMsg(mpz_class& pseudoU, mpz_class& peudoN, const string& longtrmPKI, const IsrKey&);
    void joinZKPPriMsgCrtRnd(mpz_class& uTilt, mpz_class& nTilt, const IsrKey&);
    void joinZKPPriMsgPseudoMsg(JoinSMsg&, const string& ch);
    void setPriMsg(const mpz_class& v2, Issuer*);
    bool checkPriMsgSigntr(PriMsgSgntr*, const IsrKey&);

    //help function
    bool	gen_$T_1_t();
    bool	gen_$r_f();
    bool	gen_$N_v(VerSignature*);
};

#endif // TPM_H
