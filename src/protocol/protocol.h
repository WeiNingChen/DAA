#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include "issuer.h"
#include "tpm.h"
#include "host.h"
#include "verifier.h"

using namespace std;
class Host;

class JoinProtocol 
{
public:
    JoinProtocol() {}
    ~JoinProtocol() {}

    bool operator() (Issuer*, Host*);

private:
    bool reset(Issuer*, Host*);
    bool joinZKPPriMsgTPM2Issuer(Issuer*, Host*, const mpz_class& stigma, const mpz_class& pseudoU, const mpz_class& pseudoN);
    bool joinZKPSgntrAIssuer2Host(Issuer*, Host*, const mpz_class& pseudoU);
};

class SignProtocol
{
public:
	bool operator() (Host*, Verifier*);

	bool signingTPM();
	void printVerList();
	void printHostList();
	
};

#endif // PROTOCOL_H
