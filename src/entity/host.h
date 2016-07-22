#ifndef HOST_H
#define HOST_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <map>
#include <vector>
#include "protocol.h"
#include "issuer.h"
#include "tpm.h"

class Issuer;
class IsrKey;
class Host;
class Verifier;
class TPM;
class PriMsg;
class SignProtocol;

class PriMsgSgntr  
{
    friend class Host;

public:
    PriMsgSgntr(mpz_class a, mpz_class e, PriMsg* m): _A(a), _e(e), _priMsg(m) { }
    ~PriMsgSgntr() {}

    PriMsg* getPriMsg() const { return _priMsg; }

    mpz_class get_A() const { return _A; }
    mpz_class get_e() const { return _e; }

private:
    // data member
    mpz_class   _A;
    mpz_class   _e;
    PriMsg*     _priMsg;
};

class VerSignature
{
    friend class Host;
    friend class TPM;

public:
    VerSignature(){}
    ~VerSignature(){}
    //access function
    mpz_class get_zeta() const {return zeta;}
    mpz_class get_T_1()	const {return T_1;}
    mpz_class get_T_2()	const {return T_2;}
    mpz_class get_N_v()	const {return N_v;}
    mpz_class get_c() const {return c;}
    mpz_class get_n_t()	const {return n_t;}
    mpz_class get_s_v()	const {return s_v;}
    mpz_class get_s_f0() const {return s_f0;}
    mpz_class get_s_f1() const {return s_f1;}
    mpz_class get_s_e()	const {return s_e;}
    mpz_class get_s_ee() const {return s_ee;}
    mpz_class get_s_w()	const {return s_w;}
    mpz_class get_s_ew() const {return s_ew;}
    mpz_class get_s_r()	const {return s_r;}
    mpz_class get_s_er() const {return s_er;}
    string get_msg() const {return msg;}

private:
    //data member
    mpz_class zeta, T_1, T_2, N_v, c, n_t;
    mpz_class s_v, s_f0, s_f1, s_e, s_ee, s_w, s_ew, s_r, s_er;
    string msg;
};


class Host 
{
typedef pair<Verifier*, VerSignature*>      VerPair;

    friend class JoinProtocol;
    friend class SignProtocol;

public:
    Host(string);
    ~Host() {}

    string getHostId() const { return _hostId; }

    PriMsgSgntr* getPriMsgSgntr(int i = 0) const { return _priMsgSgntrs[i]; }
    PriMsg* getPriMsg(PriMsgSgntr* s) const { return s -> _priMsg; }
    VerSignature getVerSig(Verifier* ver) const
    {
        for(size_t i=0;i<_verifierList.size();++i){
            if(ver==_verifierList[i].first) {
                VerSignature temp= *(_verifierList[i].second);
                return temp;
            }
        }
        cout<<"Can not find Verifier!!"<<endl;
        return VerSignature();
    }
    
    bool addVerifier(Verifier*);
    bool genVerSig(VerSignature*, Verifier*, PriMsgSgntr*);
    void printVer();
    void printSignature(); // for Join Protocol
    bool reset();

private:
    static vector<Host*>    _hostList;
    static vector<Host*> getHostList() { return _hostList; }

    string                  _hostId;
    TPM*                    _tpm;
    vector<PriMsgSgntr*>    _priMsgSgntrs;
    vector<VerPair>         _verifierList; //only store verifier which are already registered

    vector<RoguePriMsg*>    _blackList;

    vector<mpz_class>       _memory;
    // for Joining Protocol : [0] = nh, [1] = v2
    // for Signing Protocol

    //for Join Protocol
    mpz_class joinStigma2TPM(const string& issuerBasename, const IsrKey& pkI) const;
    string joinZKPPriMsg_ch2TPM(const mpz_class& pseudoU, const mpz_class& pseudoN, 
    const mpz_class& uTilt, const mpz_class& nTilt, const string& ni, const IsrKey& pkI);
    mpz_class joinZKPSgntrA_nh2Issuer();
    bool joinZKPSgntrAVerify(const JoinSgntrA& sgntrA, const IsrKey& pkI, const mpz_class& pseudoU);
    mpz_class getSgntrA_v2() const { return _memory[1]; }

    //help function	
    bool gen_Zeta(VerSignature*, Verifier*, PriMsgSgntr*);
    bool gen_T(VerSignature*, Verifier*, PriMsgSgntr*);
    bool gen_c_S(VerSignature*, Verifier*, PriMsgSgntr*);
    bool gen_sigProof(VerSignature*, Verifier*, PriMsgSgntr*);
    bool gen_random();
    bool gen_$T_1(VerSignature*);
    bool gen_$T_2();
    bool gen_$T_2_(VerSignature*);
    bool gen_c_h(VerSignature*, Verifier*);
};

#endif // HOST_H
