#ifndef ISSUER_H
#define ISSUER_H

#include <iostream>
#include <vector>
#include <gmp.h>
#include <gmpxx.h>
#include "message.h"
#include "util.h"
#include "scrtPrmt.h"

using namespace std;

class Issuer;

class IsrKey
{
    friend class Issuer;

public:	
    mpz_class get_n() const { return n; }
    mpz_class get_g1() const { return g1; }
    mpz_class get_g() const { return g; }
    mpz_class get_h() const { return h; }
    mpz_class get_S() const { return S; }
    mpz_class get_Z() const { return Z; }
    mpz_class get_R0() const { return R0; }
    mpz_class get_R1() const { return R1; }
    mpz_class get_gamma() const { return gamma; }
    mpz_class get_Gamma() const { return Gamma; }
    mpz_class get_rho() const { return rho; }

private:
    //public key
    mpz_class n, g1, g, h, S, Z, R0, R1, gamma, Gamma, rho;
    //private key
    mpz_class p, q;

    void keyGeneration();
};

class IsrProof
{
    friend class Issuer;

public:

private:
    mpz_class g[H_SIZE], h[H_SIZE], S[H_SIZE], Z[H_SIZE], R0[H_SIZE], R1[H_SIZE];
    void proofGeneration();
};

class Issuer
{
    friend class JoinProtocol;

public:
    Issuer(int i) : _index(i) {
        cout << "Issuer " << i << " constructing..." << endl;
        _key.keyGeneration();
        _proof.proofGeneration();
        _basename = "basename"; //
        _longtermPKI = "longtermPKI"; //
    }

    ~Issuer() {}

    int getNumber() const { return _number; }
    int getIndex() const { return _index; }
    IsrKey getPK() const { return _key;}
    IsrProof getProof() const { return _proof; }
    string getBasename() const { return _basename; }
    void setBasename(string s) { _basename = s; }

    string getLTPKI() const { return _longtermPKI; }

    bool reset();

private:
    static int  _number;
    int         _index;
    IsrKey      _key;
    IsrProof    _proof;
    string      _basename;     //
    string      _longtermPKI;  //

    vector<RoguePriMsg*>    _blackList;

    vector<mpz_class>       _memory; 
    // for Join Protocol : [0] = pseudoU, [1] = pseudoN, [2] = ni

    // for Join Protocol
    void joinSetPseudo(const mpz_class& u, const mpz_class& n);
    bool joinCheckRogueList();
    string joinZKPPriMsgNi2Host();
    bool joinZKPPriMsgVerify(const JoinSMsg&, const mpz_class& stigma);
    void joinZKPSgntrACrtSgntr(JoinSgntrA&, const mpz_class& nh);
};

#endif // ISSUER_H
