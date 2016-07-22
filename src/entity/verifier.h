#ifndef VERIFIER_H
#define VERIFIER_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include "issuer.h"
#include "host.h"
#include "tpm.h"
#include <string>
#include "protocol.h"
#include "util.h"

class Issuer;
class IsrKey;
class host;
class TPM;
class VerSignature;
class SignProtocol;

class Verifier
{
	friend class SignProtocol;

public:
	
    Verifier(string basename) { 
        _basename = basename; 
        _verifierList.push_back(this);
    };
    ~Verifier(){};
	
    string getBasename() const { return _basename; }
    
    //for signing protocol
    mpz_class getNunce() const { return 0; }
    //for verification algorithm
    bool verifySignature( VerSignature, Issuer*);
    static vector<Verifier*>	getVerList() {return _verifierList;}

private:
    string _basename;
    vector<mpz_class> _memory;
    vector<mpz_class> _rougeList;
    vector<mpz_class> _userList;

    static vector<Verifier*> _verifierList;

    //help function
    bool gen_$T_1( const VerSignature&,  const IsrKey&);
    bool gen_$T_2( const VerSignature&,  const IsrKey&);
    bool gen_$T_2_( const VerSignature&,  const IsrKey&);
    bool gen_$N_v( const VerSignature&, const  IsrKey&);
    bool gen_c   (const VerSignature&, const IsrKey&);
};

#endif // VERIFIER_H
