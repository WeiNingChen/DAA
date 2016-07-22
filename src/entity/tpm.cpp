#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <cmath>
#include "issuer.h"
#include "tpm.h"
#include "util.h"
#include "scrtPrmt.h"

using namespace std;

/*******************************************************/
/*    class TPM member functions for Join Protocol     */
/*******************************************************/
bool 
TPM::joinCheckStigma(const mpz_class& stigma, const IsrKey& pkI) const {
    mpz_class n;
    mpz_powm(n.get_mpz_t(), stigma.get_mpz_t(), pkI.get_rho().get_mpz_t(), pkI.get_Gamma().get_mpz_t());
    if (n == 1) { 
        _memory.push_back(stigma);
        return true;
    }
    else return false;
}

void 
TPM::joinCrtPriMsg(mpz_class& pseudoU, mpz_class& pseudoN, const string& longtrmPKI, const IsrKey& pkI)
{
    size_t i = (RHO_SIZE + ZKP_SIZE) / H_SIZE;
    string _hashLTPKI = _hash(longtrmPKI);
    string str = "";
    for (size_t t = 0; t <= i; ++t)
        str = str + _hash(_hash(_daaSeed + _hashLTPKI) + myInt2Str((int)_cnt, 10) + myInt2Str((int)t, 10));
    mpz_class f; 
    mpz_mod(f.get_mpz_t(), myStr2Int(str, 16).get_mpz_t(), pkI.get_rho().get_mpz_t());

    mpz_class f0, f1;
    if (F_SIZE <= 1024) f1 = pow(2, (int)F_SIZE);
    else mpz_ui_pow_ui(f1.get_mpz_t(), 2, F_SIZE);
    f0 = f - f1 * (f / f1);
    f1 = f / f1;

    mpz_class v1 = nBitsGen(RSA_SIZE + ZKP_SIZE);

    mpz_class u1, u2, u3;
    mpz_powm(u1.get_mpz_t(), pkI.get_R0().get_mpz_t(), f0.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(u2.get_mpz_t(), pkI.get_R1().get_mpz_t(), f1.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(u3.get_mpz_t(), pkI.get_S().get_mpz_t(), v1.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_class u = u1 * u2 * u3;
    mpz_mod(pseudoU.get_mpz_t(), u.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(pseudoN.get_mpz_t(), _memory[0].get_mpz_t(), f.get_mpz_t(), pkI.get_Gamma().get_mpz_t());
    
    PriMsg* newPriMsg = new PriMsg(f0, f1, v1);
    _priMsgs.push_back(newPriMsg);
}
    
void 
TPM::joinZKPPriMsgCrtRnd(mpz_class& uTilt, mpz_class& nTilt, const IsrKey& pkI)
{
    mpz_class f0Rnd = nBitsGen(F_SIZE + ZKP_SIZE + H_SIZE);
    mpz_class f1Rnd = nBitsGen(F_SIZE + ZKP_SIZE + H_SIZE);
    mpz_class v1Rnd = nBitsGen(RSA_SIZE + ZKP_SIZE * 2 + H_SIZE);

    mpz_class u1, u2, u3;
    mpz_powm(u1.get_mpz_t(), pkI.get_R0().get_mpz_t(), f0Rnd.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(u2.get_mpz_t(), pkI.get_R1().get_mpz_t(), f1Rnd.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(u3.get_mpz_t(), pkI.get_S().get_mpz_t(), v1Rnd.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_class u = u1 * u2 * u3;
    mpz_mod(uTilt.get_mpz_t(), u.get_mpz_t(), pkI.get_n().get_mpz_t());
    
    mpz_class fRnd;
    if (F_SIZE <= 1024) fRnd = pow(2, (int)F_SIZE);
    else mpz_ui_pow_ui(fRnd.get_mpz_t(), 2, F_SIZE);
    fRnd = f0Rnd + f1Rnd * fRnd;
    mpz_powm(nTilt.get_mpz_t(), _memory[0].get_mpz_t(), fRnd.get_mpz_t(), pkI.get_Gamma().get_mpz_t());

    PriMsg* rndPriMsg = new PriMsg(f0Rnd, f1Rnd, v1Rnd);
    _priMsgs.push_back(rndPriMsg);
}
    
void 
TPM::joinZKPPriMsgPseudoMsg(JoinSMsg& sMsg, const string& ch)
{
    string nt = nBitsGen(ZKP_SIZE).get_str(16);
    string c = _hash(ch + nt);

    mpz_class cNum = myStr2Int(c, 16);
    size_t size = _priMsgs.size();
    PriMsg* priMsg = _priMsgs[size-2];
    PriMsg* priMsgRnd = _priMsgs[size-1];
    mpz_class sf0 = priMsgRnd -> _f0 + cNum * priMsg -> _f0;
    mpz_class sf1 = priMsgRnd -> _f1 + cNum * priMsg -> _f1;
    mpz_class sv1 = priMsgRnd -> _v + cNum * priMsg -> _v;

    sMsg = JoinSMsg(c, nt, sf0, sf1, sv1);

    delete priMsgRnd;
    _priMsgs.pop_back();
}
    
void 
TPM::setPriMsg(const mpz_class& v2, Issuer* issuer)
{
    size_t size = _priMsgs.size();
    PriMsg* newPriMsg = _priMsgs[size-1];
    newPriMsg -> setV(newPriMsg -> _v + v2);

    _issuer = issuer;
}
    
bool 
TPM::checkPriMsgSigntr(PriMsgSgntr* sgntrA, const IsrKey& pkI)
{
    mpz_class r, r1, r2, r3, r4;
    mpz_powm(r1.get_mpz_t(), pkI.get_R0().get_mpz_t(), _priMsgs.back() -> _f0.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(r2.get_mpz_t(), pkI.get_R1().get_mpz_t(), _priMsgs.back() -> _f1.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(r3.get_mpz_t(), pkI.get_S().get_mpz_t(), _priMsgs.back() -> _v.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(r4.get_mpz_t(), sgntrA -> get_A().get_mpz_t(), sgntrA -> get_e().get_mpz_t(), pkI.get_n().get_mpz_t());
    r = r1 * r2 * r3 * r4;
    mpz_mod(r.get_mpz_t(), r.get_mpz_t(), pkI.get_n().get_mpz_t());

    if (r == pkI.get_Z()) return true;
    else return false;
}

/********************************************************************************************************************/
/********************************************************************************************************************/

bool
TPM::gen_N_v(VerSignature* verSig, PriMsgSgntr* sig)
{
    //for compile
    PriMsg* _priMsg=sig->getPriMsg();
    //
    if(_priMsg==NULL||_issuer==NULL) return false;
    mpz_class n_v,_base,_power,_module,f_len;
    f_len=2;
    f_len=f_len^F_SIZE;
    _base=verSig->zeta;
    _power=_priMsg->_f0;
    _power+=_priMsg->_f1*f_len;
    _module=_issuer->getPK().get_Gamma();
    mpz_powm(n_v.get_mpz_t(), _base.get_mpz_t(), _power.get_mpz_t(), _module.get_mpz_t());
    verSig->N_v=n_v;
    return true;
}

bool
TPM::gen_n_t(VerSignature* verSig, PriMsgSgntr* sig)
{
    verSig->n_t=nBitsGen(ZKP_SIZE);
    return true;
}

bool 
TPM::gen_random(VerSignature* verSig, PriMsgSgntr* sig)
{

    if(!_memory.empty()){ 
        //cout<<"Warning: Clear TPM's Meomory..."<<endl;
        _memory.clear();
    }

    mpz_class r_v, r_f0, r_f1;
    r_v=nBitsGen(V_SIZE+ZKP_SIZE+H_SIZE);
    r_f0=nBitsGen(F_SIZE+ZKP_SIZE+H_SIZE);
    r_f1=nBitsGen(F_SIZE+ZKP_SIZE+H_SIZE);
    _memory.push_back(r_f0);
    _memory.push_back(r_f1);
    _memory.push_back(r_v);

    //generate $T_1t, $N_v
    if(!gen_$T_1_t()){
        cout<<"Warning: Generating  r_v, r_f0, r_f1 error..."<<endl;
        return false;
    }
    if(!gen_$r_f()){
        cout<<"Warning: Generating $r_f error..."<<endl;
        return false;
    }
    if(!gen_$N_v(verSig)){
        cout<<"Warning: Generating $r_f error..."<<endl;
        return false;
    }
    if(_memory.size()!=6){
        cout<<"Warning: Generating Random error..."<<endl;
        return false;
    }
    return true;
}

bool
TPM::gen_c(VerSignature* verSig, Verifier* ver, mpz_class c_h)
{
    if(ver==NULL||verSig==NULL) return false;
    //bool b=0;
    string _msg="01234";
    string _key;
    _key+=c_h.get_str(16);
    _key+=verSig->n_t.get_str();
    _key=_hash(_key);
    //if(b) _key+="1";
    //else _key+="0";
    _key+=_msg;
    verSig->msg=_msg;
    verSig->c=mpz_class(_hash(_key),16);
    return true;
}


//help function to gen_random

/* _memory[0]:r_f0
 * _memory[1]:r_f1
 * _memory[2]:r_v
 * _memory[3]:$T
 * _memory[4]:$r_f
 * _memory[5]:$N_v
 */

bool
TPM::gen_$T_1_t()
{
    if(_memory.size()!=3) return false;
    mpz_class $T;
    mpz_class _R0 ;//= _issuer->getPK().get_R0();
    mpz_class _R1 ;//= _issuer->getPK().get_R1();
    mpz_class _S  ;//= _issuer->getPK().get_S();

    mpz_powm(_R0.get_mpz_t(),_issuer->getPK().get_R0().get_mpz_t(),_memory[0].get_mpz_t(),_issuer->getPK().get_n().get_mpz_t());
    mpz_powm(_R1.get_mpz_t(),_issuer->getPK().get_R1().get_mpz_t(),_memory[1].get_mpz_t(),_issuer->getPK().get_n().get_mpz_t());
    mpz_powm(_S.get_mpz_t(),_issuer->getPK().get_S().get_mpz_t(),_memory[2].get_mpz_t(),_issuer->getPK().get_n().get_mpz_t());

    $T=(_R0*_R1)%_issuer->getPK().get_n();
    $T=($T*_S)%_issuer->getPK().get_n();
    _memory.push_back($T);
    return true;
}

bool
TPM::gen_$r_f()
{
    if(_memory.size()!=4) return false;
    mpz_class $r=_memory[0]%_issuer->getPK().get_rho();
    mpz_class z=2;
    z=z^(F_SIZE);
    $r+=_memory[1]*z%_issuer->getPK().get_rho();
    $r%_issuer->getPK().get_rho();
    _memory.push_back($r);
    return true;
}

bool
TPM::gen_$N_v(VerSignature* verSig)
{
    if(_memory.size()!=5||verSig==NULL) return false;
    mpz_class $N, _zeta, _Gamma;
    _zeta = verSig->zeta;
    _Gamma= _issuer->getPK().get_Gamma();
    mpz_powm($N.get_mpz_t(), _zeta.get_mpz_t(), _memory[4].get_mpz_t(),_Gamma.get_mpz_t());
    _memory.push_back($N);
   // cout<<"in TPM"<<endl;
    //cout<<"$N_v"<<endl<<$N<<endl<<endl;
    return true;
}

/* _memory[0]:r_f0
 * _memory[1]:r_f1
 * _memory[2]:r_v
 * _memory[3]:$T
 * _memory[4]:$r_f
 * _memory[5]:$N_v
 */

bool
TPM::gen_sigProof(VerSignature* verSig, PriMsgSgntr* sig)
{
    //for test only
    PriMsg* _priMsg=sig->getPriMsg();
    //if(_priMsg->_f.size()!=2) return false;
    //
    if(_memory.size()!=6)   return false;
    mpz_class c= verSig->get_c();

    verSig->s_v= _memory[2]+c*_priMsg->_v;
    verSig->s_f0= _memory[0]+c*_priMsg->_f0;
    verSig->s_f1= _memory[1]+c*_priMsg->_f1;
    return true;
}

bool
TPM::reset()
{
    _memory.clear();
    return true;
}
