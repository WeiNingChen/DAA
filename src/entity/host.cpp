#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <string>
#include <cmath>
#include "issuer.h"
#include "host.h"
#include "tpm.h"
#include "verifier.h"
#include "util.h"
#include "scrtPrmt.h"
# include <iomanip>

using namespace std;

//#define POW(A,B,C,D);
//mpz_powm(A.get_mpz_t(),B.get_mpz_t(),C,get_mpz_t(),D.get_mpz_t())

vector<Host*> Host::_hostList;

Host::Host(string s)
{
    _hostId = s;
    _tpm = new TPM(this);
    _hostList.push_back(this);
}
    
/*******************************************************/
/*    class Host member functions for Join Protocol    */
/*******************************************************/
mpz_class
Host::joinStigma2TPM(const string& issuerBasename, const IsrKey& pkI) const {
    mpz_class stigma;
    mpz_class base = myStr2Int(_hash("1" + issuerBasename), 16);  // _hash_GM !!!!
    mpz_class exp = (pkI.get_Gamma() - 1) / pkI.get_rho();
    mpz_powm(stigma.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), pkI.get_Gamma().get_mpz_t());
    return stigma;
}
    
string 
Host::joinZKPPriMsg_ch2TPM(const mpz_class& pseudoU, const mpz_class& pseudoN, 
        const mpz_class& uTilt, const mpz_class& nTilt, const string& ni, const IsrKey& pkI)
{
    string str = pkI.get_n().get_str(16) + pkI.get_R0().get_str(16) + pkI.get_R1().get_str(16) + pkI.get_S().get_str(16)
                 + pseudoU.get_str(16) + pseudoN.get_str(16) + uTilt.get_str(16) + nTilt.get_str(16) + ni;
    return _hash(str);
}
    
mpz_class 
Host::joinZKPSgntrA_nh2Issuer()
{
    mpz_class nh = nBitsGen(ZKP_SIZE);
    _memory.push_back(nh);
    return nh;
}
    
bool 
Host::joinZKPSgntrAVerify(const JoinSgntrA& sgntrA, const IsrKey& pkI, const mpz_class& pseudoU)
{
    // Check whether e is prime

    mpz_class cmp, range;
    if (E_SIZE <= 1024) cmp = pow(2, (int)E_SIZE - 1);
    else mpz_ui_pow_ui(cmp.get_mpz_t(), 2, E_SIZE - 1);
    if (E1_SIZE <= 1024) range = pow(2, (int)E1_SIZE - 1);
    else mpz_ui_pow_ui(range.get_mpz_t(), 2, E1_SIZE - 1);
    if (sgntrA.get_e() < cmp || sgntrA.get_e() > cmp + range) { 
        cerr << "Signature e is not in the correct range!!" << endl;
        return false;
    }

    mpz_class aHat, a0, a1, a2, a3;
    mpz_class seNeg = -1 * sgntrA.get_se();
    mpz_class seNegV2 = sgntrA.get_v2() * seNeg;
    mpz_class cNum = myStr2Int(sgntrA.get_c1(), 16);
    mpz_powm(a0.get_mpz_t(), sgntrA.get_A().get_mpz_t(), cNum.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(a1.get_mpz_t(), pkI.get_Z().get_mpz_t(), sgntrA.get_se().get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(a2.get_mpz_t(), pseudoU.get_mpz_t(), seNeg.get_mpz_t(), pkI.get_n().get_mpz_t());
    mpz_powm(a3.get_mpz_t(), pkI.get_S().get_mpz_t(), seNegV2.get_mpz_t(), pkI.get_n().get_mpz_t());
    aHat = a0 * a1 * a2 * a3;
    mpz_mod(aHat.get_mpz_t(), aHat.get_mpz_t(), pkI.get_n().get_mpz_t());

    string c2 = pkI.get_n().get_str(16) + pkI.get_Z().get_str(16) + pkI.get_S().get_str(16)
                + pseudoU.get_str(16) + sgntrA.get_v2().get_str(16) + sgntrA.get_A().get_str(16)
                + aHat.get_str(16) + _memory[0].get_str(16);
    c2 = _hash(c2);
    if (c2 != sgntrA.get_c1()) {
        cerr << "The _hash value c is not different!!" << endl;
        return false;
    }

    PriMsgSgntr* newSgntr = new PriMsgSgntr(sgntrA.get_A(), sgntrA.get_e(), _tpm -> joinGetPriMsg());
    _priMsgSgntrs.push_back(newSgntr);
    _memory.push_back(sgntrA.get_v2());
    return true;
}
    
void 
Host::printSignature() // for Join Protocol
{
    cout << "Host " << _hostId << "'s signature for private message of TPM :" << endl
         << " A :" << endl
         << _priMsgSgntrs.back() -> _A << endl
         << " e :" << endl
         << _priMsgSgntrs.back() -> _e << endl
         << endl << endl;
}
    
/********************************************************************************************************************/
/********************************************************************************************************************/

bool 
Host::addVerifier(Verifier* ver)
{
	if(ver==NULL) return false;
	_verifierList.push_back(VerPair(ver,NULL));
	return true;
}

bool
Host::genVerSig(VerSignature* XXX, Verifier* ver, PriMsgSgntr* XX)
{
	
	if(_tpm->getIssuer()==NULL){
		cerr<<"Not join yet..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(_priMsgSgntrs.empty()){
		cerr<<"No signature found!!"<<endl;
		return false;
	}
	
	PriMsgSgntr* sig=_priMsgSgntrs[0];
	VerSignature* verSig= new VerSignature;

	if(!gen_Zeta(verSig, ver, sig)){
		cerr<<"Fail to generate Zeta..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(!gen_T(verSig, ver, sig)){
		cerr<<"Fail to generate T..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(!_tpm->gen_N_v( verSig, sig)){
		cerr<<"Fail to generate N_v..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(!_tpm->gen_n_t(verSig, sig)){
		cerr<<"fail to generate n_t..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	// to store temporary value from TPM
	if(_tpm->gen_random(verSig,sig)) ;//cout<<"Generate random noise in TPM sucessfully !"<<endl;
	else{
		cerr<<"Fail to generate random in TPM..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(!gen_random()){
		cerr<<"Fail to generate random in Host..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	} 
	if(!gen_$T_1(verSig)){
		cerr<<"Fail to generate $T_1 in Host..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	} 
	if(!gen_$T_2()){
		cerr<<"Fail to generate $T_2 in Host..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	} 
	if(!gen_$T_2_(verSig)){
		cerr<<"Fail to generate $T_2_ in Host..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	} 
	//cout<<"Generate random noise in Host sucessfully !"<<endl;
	if(!gen_c_h(verSig,ver)){
		cerr<<"Fail to generate c_h in Host..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(!_tpm->gen_c(verSig,ver,_memory[11])){
		cerr<<"Fail to generate c in TPM..."<<endl;
		cerr<<"Generating Signature Proof stop."<<endl;
		return false;
	}
	if(!_tpm->gen_sigProof(verSig,sig)){
		return false;
	}
	if(!gen_sigProof(verSig,ver,sig)){
		return false;
	}
	cout<<"Adding certificate..."<<endl;
	for(size_t i=0;i<_verifierList.size();++i)
	{
		if(_verifierList[i].first==ver) _verifierList[i].second=verSig;
	}
	return true;
}

void 
Host::printVer()
{
	cout << "==========================================================" << endl
         << "=            Verifier List of Host \"" << _hostId << "\"";
    for (size_t i = 20; i > _hostId.size(); --i) cout << " ";
    cout << "=" << endl
	     << "==========================================================" << endl;
	for(size_t i = 0; i < _verifierList.size(); ++i) {
		if(_verifierList[i].second != NULL) {
			cout << "= " << setw(55) << left << _verifierList[i].first -> getBasename() << "=" << endl
                 << "= Certificate : " << hex << _verifierList[i].second -> get_c() << " =" << endl
	             << "=                                                        =" << endl;
		}
	}
	cout << "==========================================================" << endl
	     << endl << endl;
}
bool
Host::reset()
{
	_memory.clear();
	return true;
}

//help function for genVerSig()
bool
Host::gen_Zeta(VerSignature* verSig, Verifier* ver, PriMsgSgntr* sig)
{
	if(ver==NULL)	
	{
		cout<<"ver is NULL!"<<endl;
		return false;
	}
	if(verSig==NULL) 
	{
		cout<<"verSig is NULL!"<<endl;
		return false;
	}
	// Generate zeta
	mpz_class _zeta,_base,_power;
	string _basename = ver->getBasename();
	Issuer* _isr = _tpm->getIssuer();

	if(_basename==""){
		_base=_isr->getPK().get_gamma();
		_power=nBitsGen(RHO_SIZE);
		//Calculate gamma^R(mod Gamma)
		mpz_powm(_zeta.get_mpz_t(),_base.get_mpz_t(),_power.get_mpz_t(),_isr->getPK().get_Gamma().get_mpz_t());
	}
	else{
		string my_hash=_hash("1"+_basename);
		_base=myStr2Int(my_hash,16);
		_power=(_isr->getPK().get_Gamma()-1)/_isr->getPK().get_rho();
		mpz_powm(_zeta.get_mpz_t(),_base.get_mpz_t(),_power.get_mpz_t(),_isr->getPK().get_Gamma().get_mpz_t());
	}
	verSig->zeta=_zeta;
	return true;
}


bool
Host::gen_T(VerSignature* verSig, Verifier* ver, PriMsgSgntr* sig)
{
	if(sig==NULL) return false;
	Issuer* _isr = _tpm->getIssuer();

	mpz_class t_1,t_2,temp,temp1,temp2;
	mpz_class w,r;
	w=nBitsGen(RSA_SIZE+ZKP_SIZE);
	r=nBitsGen(RSA_SIZE+ZKP_SIZE);

	//Generate T1
	mpz_powm(temp.get_mpz_t(),_isr->getPK().get_h().get_mpz_t(),w.get_mpz_t(),_isr->getPK().get_n().get_mpz_t());
	t_1 = (sig->_A)*temp%(_isr->getPK().get_n());

	//Generate T2
	mpz_powm(temp.get_mpz_t(),_isr->getPK().get_g().get_mpz_t(),w.get_mpz_t(),_isr->getPK().get_n().get_mpz_t());
	mpz_powm(temp1.get_mpz_t(),_isr->getPK().get_h().get_mpz_t(),(sig->_e).get_mpz_t(),_isr->getPK().get_n().get_mpz_t());
	mpz_powm(temp2.get_mpz_t(),_isr->getPK().get_g1().get_mpz_t(),r.get_mpz_t(),_isr->getPK().get_n().get_mpz_t());
	t_2=temp*temp1%(_isr->getPK().get_n());
	t_2=t_2*temp2%(_isr->getPK().get_n());
	verSig->T_1=t_1;
	verSig->T_2=t_2;
	
	if(!_memory.empty()){
		//cout<<"Warning: Clear host's memory..."<<endl;
		_memory.clear();
	}
	_memory.push_back(w);
	_memory.push_back(r);
	return true;
}

/*
0_memory.push_back(w);
1_memory,push_back(r);
2_memory.push_back(r_e);
3_memory.push_back(r_ee);
4_memory.push_back(r_w);
5_memory.push_back(r_r);
6_memory.push_back(r_ew);
7_memory.push_back(r_er);
8_memory.push_back($T_1);
9_memory.push_back($T_2);
10_memory.push_back($T_2_);
11_memory.push_back(c_h);
*/

//Create c,s
bool
Host::gen_sigProof(VerSignature* verSig, Verifier* ver, PriMsgSgntr* sig)
{
	if(_memory.size()!=12)	return false;
	
	mpz_class c= verSig->get_c();
	mpz_class temp;

	temp=2;
	temp=temp^(E_SIZE-1);
	verSig->s_e=_memory[2]+c*(sig->_e-temp);
	//cout<<"s_e: "<<verSig->s_e<<endl<<endl;
	verSig->s_ee=_memory[3]+c*(sig->_e)*(sig->_e);
	verSig->s_w=_memory[4]+c*_memory[0];
	verSig->s_ew=_memory[6]+c*_memory[0]*(sig->_e);
	verSig->s_r=_memory[5]+c*_memory[1];
	verSig->s_er=_memory[7]+c*_memory[1]*(sig->_e);
	return true;
}

//help finction for gen_sigProof()
bool 
Host::gen_random()
{	
	if(_memory.size()!=2) 	return false;

	mpz_class r_e,r_ee,r_w,r_r,r_ew,r_er;
	r_e=nBitsGen(E1_SIZE+ZKP_SIZE+H_SIZE);
	r_ee=nBitsGen(E_SIZE+ZKP_SIZE+H_SIZE);
	r_w=nBitsGen(RSA_SIZE+2*ZKP_SIZE+H_SIZE);
	r_r=nBitsGen(RSA_SIZE+2*ZKP_SIZE+H_SIZE);
	r_ew=nBitsGen(E_SIZE+RSA_SIZE+2*ZKP_SIZE+H_SIZE+1);
	r_er=nBitsGen(E_SIZE+RSA_SIZE+2*ZKP_SIZE+H_SIZE+1);

	_memory.push_back(r_e);
	//cout<<"r_e: "<<r_e<<endl<<endl;
	_memory.push_back(r_ee);
	//cout<<"r_ee: "<<r_ee<<endl<<endl;
	_memory.push_back(r_w);
	//cout<<"r_w: "<<r_w<<endl<<endl;
	_memory.push_back(r_r);
	//cout<<"r_r: "<<r_r<<endl<<endl;
	_memory.push_back(r_ew);
	//cout<<"r_ew: "<<r_ew<<endl<<endl;
	_memory.push_back(r_er);
	//cout<<"r_er: "<<r_er<<endl<<endl;

	return true;
}

bool 
Host::gen_$T_1(VerSignature* verSig)
{
	if(_memory.size()!=8) 	return false;

	mpz_class h=_tpm->getIssuer()->getPK().get_h();
	mpz_class n=_tpm->getIssuer()->getPK().get_n();
	mpz_class $T_1_t=_tpm->get_$T_1_t();
	mpz_class T_1=verSig->T_1;
	mpz_class $T_1,temp,temp2;

	mpz_powm(temp.get_mpz_t(),T_1.get_mpz_t(),_memory[2].get_mpz_t(),n.get_mpz_t());
	$T_1=($T_1_t*temp)%n;

	temp2=-1*_memory[6];
	mpz_powm(temp.get_mpz_t(),h.get_mpz_t(),temp2.get_mpz_t(),n.get_mpz_t());
	$T_1=($T_1*temp)%n;

	_memory.push_back($T_1);
	//cout<<"$T_1: "<<$T_1<<endl<<endl;
	return true;
}

bool 
Host::gen_$T_2()
{
	if(_memory.size()!=9) return false;

	mpz_class g=_tpm->getIssuer()->getPK().get_g();
	mpz_class h=_tpm->getIssuer()->getPK().get_h();
	mpz_class g1=_tpm->getIssuer()->getPK().get_g1();
	mpz_class n=_tpm->getIssuer()->getPK().get_n();
	mpz_class $T_2,temp;

	mpz_powm(temp.get_mpz_t(),g.get_mpz_t(),_memory[4].get_mpz_t(),n.get_mpz_t());
	$T_2=temp;
	mpz_powm(temp.get_mpz_t(),h.get_mpz_t(),_memory[2].get_mpz_t(),n.get_mpz_t());
	$T_2=(temp*$T_2)%n;
	mpz_powm(temp.get_mpz_t(),g1.get_mpz_t(),_memory[5].get_mpz_t(),n.get_mpz_t());
	$T_2=(temp*$T_2)%n;

	_memory.push_back($T_2);
	//cout<<"$T_2: "<<$T_2<<endl<<endl;
	return true;
}

/*
0_memory.push_back(w);
1_memory,push_back(r);
2_memory.push_back(r_e);
3_memory.push_back(r_ee);
4_memory.push_back(r_w);
5_memory.push_back(r_r);
6_memory.push_back(r_ew);
7_memory.push_back(r_er);
8_memory.push_back($T_1);
9_memory.push_back($T_2);
10_memory.push_back($T_2_);
11_memory.push_back(c_h);
*/

bool 
Host::gen_$T_2_(VerSignature* verSig)
{
	if(_memory.size()!=10) return false;

	mpz_class g=_tpm->getIssuer()->getPK().get_g();
	mpz_class h=_tpm->getIssuer()->getPK().get_h();
	mpz_class g1=_tpm->getIssuer()->getPK().get_g1();
	mpz_class n=_tpm->getIssuer()->getPK().get_n();
	mpz_class $T_2_,temp,temp2;

	temp2=-1*_memory[2];
	mpz_powm(temp.get_mpz_t(), verSig->T_2.get_mpz_t(), temp2.get_mpz_t(),n.get_mpz_t());
	$T_2_=temp;
	mpz_powm(temp.get_mpz_t(),g.get_mpz_t(),_memory[6].get_mpz_t(),n.get_mpz_t());
	$T_2_=(temp*$T_2_)%n;
	mpz_powm(temp.get_mpz_t(),h.get_mpz_t(),_memory[3].get_mpz_t(),n.get_mpz_t());
	$T_2_=(temp*$T_2_)%n;
	mpz_powm(temp.get_mpz_t(),g1.get_mpz_t(),_memory[7].get_mpz_t(),n.get_mpz_t());
	$T_2_=(temp*$T_2_)%n;

	_memory.push_back($T_2_);
	//cout<<"$T_2_: "<<$T_2_<<endl<<endl;
	return true;
}

bool
Host::gen_c_h(VerSignature* verSig, Verifier* ver)
{
	if(_memory.size()!=11) return false;
	string _key,_c_h;
	//H((n||g||g1||h||R0||R1||S||Z||Gamma||gamma||rho)||zeta||(T_1||T_2)||Nv||($T1||$T2||$T'2||$Nv)||n_v)
	
	// issuer PK
	_key+=_tpm->getIssuer()->getPK().get_n().get_str();
	_key+=_tpm->getIssuer()->getPK().get_g().get_str();
	_key+=_tpm->getIssuer()->getPK().get_g1().get_str();
	_key+=_tpm->getIssuer()->getPK().get_h().get_str();
	_key+=_tpm->getIssuer()->getPK().get_R0().get_str();
	_key+=_tpm->getIssuer()->getPK().get_R1().get_str();
	_key+=_tpm->getIssuer()->getPK().get_S().get_str();
	_key+=_tpm->getIssuer()->getPK().get_Z().get_str();
	_key+=_tpm->getIssuer()->getPK().get_Gamma().get_str();
	_key+=_tpm->getIssuer()->getPK().get_gamma().get_str();
	_key+=_tpm->getIssuer()->getPK().get_rho().get_str();
	//cout<<"_key in host:"<<_key<<endl<<endl;
	//verSig
	_key+=verSig->zeta.get_str();
	_key+=verSig->T_1.get_str();
	_key+=verSig->T_2.get_str();
	_key+=verSig->N_v.get_str();
	//cout<<"In Host"<<endl<<endl;
	//noise
	_key+=_memory[8].get_str();
	//cout<<"$T_1 : "<<_memory[8].get_str()<<endl<<endl;
	_key+=_memory[9].get_str();
	//cout<<"$T_2 : "<<_memory[9].get_str()<<endl<<endl;
	_key+=_memory[10].get_str();
	//cout<<"$T_2_ : "<<_memory[10].get_str()<<endl<<endl;
	//TPM
	_key+=_tpm->get_$N_v().get_str();
	//cout<<"$N_v : "<<_tpm->get_$N_v().get_str()<<endl<<endl;
	_key+=ver->getNunce().get_str();
	//cout<<"_key.length(): "<<_key.length()<<endl;
	/*cout<<
	"_memory.push_back(w)"<<endl<<_memory[0]<<endl<<endl<<
	"_memory,push_back(r)"<<endl<<_memory[1]<<endl<<endl<<
	"_memory.push_back(r_e)"<<endl<<_memory[2]<<endl<<endl<<
	"_memory.push_back(r_ee)"<<endl<<_memory[3]<<endl<<endl<<
	"_memory.push_back(r_w)"<<endl<<_memory[4]<<endl<<endl<<
	"_memory.push_back(r_r)"<<endl<<_memory[5]<<endl<<endl<<
	"_memory.push_back(r_ew)"<<endl<<_memory[6]<<endl<<endl<<
	"_memory.push_back(r_er)"<<endl<<_memory[7]<<endl<<endl<<
	"_memory.push_back($T_1)"<<endl<<_memory[8]<<endl<<endl<<
	"_memory.push_back($T_2)"<<endl<<_memory[9]<<endl<<endl<<
	"_memory.push_back($T_2_)"<<endl<<_memory[10]<<endl<<endl;
	*/

	_c_h=_hash(_key);
	//cout<<"_c_h"<<endl<<_c_h<<endl<<endl;
	_memory.push_back(myStr2Int(_c_h,16));
	return true;
}
