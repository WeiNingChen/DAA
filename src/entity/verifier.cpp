#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include "host.h"
#include "tpm.h"
#include "verifier.h"
#include "scrtPrmt.h"

using namespace std;
#ifndef	  POW
#define  POWM(A,B,C,D)	mpz_powm(A.get_mpz_t(),B.get_mpz_t(),C.get_mpz_t(),D.get_mpz_t())	
#endif

vector<Verifier*> Verifier::_verifierList;

bool
Verifier::verifySignature( VerSignature verSig, Issuer* isr)
{
	if(!isr){
		cerr<<"Unidentified Issuer..."<<endl;
		cerr<<"Fail to verify Signature !"<<endl;
		return false;
	}
	
	IsrKey _isrKey=isr->getPK();
	if(!gen_$T_1(verSig,  _isrKey)){
		cerr<<"Fail to generate $T_1"<<endl;
		return false; 
	}
	if(!gen_$T_2(verSig, _isrKey)){
		cerr<<"Fail to generate $T_2"<<endl;
		return false; 
	}
	if(!gen_$T_2_(verSig, _isrKey)){
		cerr<<"Fail to generate $T_2_"<<endl;
		return false; 
	}
	if(!gen_$N_v(verSig, _isrKey)){
		cerr<<"Fail to generate $N_v"<<endl;
		return false; 
	}
	if(!gen_c(verSig,_isrKey)){
		cerr<<"Fail to generate c"<<endl;
		return false;
	}
	//cout<<endl<<"Certficate in verifier:"<<endl<<hex<<_memory[4]<<endl;
	//cout<<"Certificate in host :"<<endl<<hex<<verSig.get_c()<<endl<<endl;
	if(_memory[4]==verSig.get_c()) return true;
	return false;
}


//help function for verifySignature
/*
_memory[0]:_memory.push_back($T_1);
_memory[1]:_memory.push_back($T_2);
_memory[2]:_memory.push_back($T_2_);
_memory[3]:_memory.push_back($N_v);
*/

bool
Verifier::gen_$T_1( const VerSignature& verSig, const  IsrKey& isrKey)
{
	mpz_class $T_1,temp,_power;
	mpz_class n=isrKey.get_n();

	//generate temp value
	_power=(-1)*verSig.get_c();
	POWM(temp, isrKey.get_Z(), _power, n);
	$T_1=temp;

	temp=2;
	_power=verSig.get_s_e()+verSig.get_c()*(temp^(E_SIZE-1));
	POWM(temp, verSig.get_T_1(), _power, n);
	$T_1=($T_1*temp)%n;

	POWM(temp, isrKey.get_R0(), verSig.get_s_f0(), n);
	$T_1=($T_1*temp)%n;

	POWM(temp, isrKey.get_R1(), verSig.get_s_f1(), n);
	$T_1=($T_1*temp)%n;

	POWM(temp, isrKey.get_S(), verSig.get_s_v(), n);
	$T_1=($T_1*temp)%n;

	_power=(-1)*verSig.get_s_ew();
	POWM(temp, isrKey.get_h(), _power, n);
	$T_1=($T_1*temp)%n;

	//check memory
	if(!_memory.empty()){
		//cerr<<"Warning: Clear Verifier's Memory..."<<endl;
		_memory.clear();
	}
	_memory.push_back($T_1);
	return true;
}

bool
Verifier::gen_$T_2( const VerSignature& verSig, const IsrKey& isrKey)
{
	mpz_class $T_2,temp,_power;
	mpz_class n=isrKey.get_n();

	//generate temp value
	_power=(-1)*verSig.get_c();
	POWM(temp, verSig.get_T_2(), _power,n);
	$T_2=temp;

	POWM(temp, isrKey.get_g(), verSig.get_s_w(), n);
	$T_2=($T_2*temp)%n;

	temp=2;
	_power=verSig.get_s_e()+verSig.get_c()*(temp^(E_SIZE-1));
	POWM(temp, isrKey.get_h(), _power, n);
	$T_2=($T_2*temp)%n;

	POWM(temp, isrKey.get_g1(), verSig.get_s_r(), n);
	$T_2=($T_2*temp)%n;
	//

	if(_memory.size()!=1)	return false;
	_memory.push_back($T_2);
	return true;
}

bool
Verifier::gen_$T_2_( const VerSignature& verSig, const  IsrKey& isrKey)
{
	mpz_class $T_2_,temp,_power;
	mpz_class n=isrKey.get_n();
	//generate temp value
	temp=2;
	_power=verSig.get_s_e()+verSig.get_c()*(temp^(E_SIZE-1));
	_power=-1*_power;
	POWM(temp, verSig.get_T_2(), _power, n);
	$T_2_=temp;

	POWM(temp, isrKey.get_g(), verSig.get_s_ew(), n);
	$T_2_=($T_2_*temp)%n;

	POWM(temp, isrKey.get_h(), verSig.get_s_ee(), n);
	$T_2_=($T_2_*temp)%n;	

	POWM(temp, isrKey.get_g1(), verSig.get_s_er(), n);
	$T_2_=($T_2_*temp)%n;
	//

	if(_memory.size()!=2)	return false;
	_memory.push_back($T_2_);
	return true;
}

bool
Verifier::gen_$N_v( const VerSignature& verSig, const IsrKey& isrKey)
{
	mpz_class $N_v,temp,_power;
	mpz_class n=isrKey.get_Gamma();
	//generate temp value
	_power=(-1)*verSig.get_c();
	POWM(temp, verSig.get_N_v(), _power,n);
	$N_v=temp;

	temp=2;
	_power=verSig.get_s_f0()+verSig.get_s_f1()*(temp^(F_SIZE));
	POWM(temp, verSig.get_zeta(), _power, n);
	$N_v=($N_v*temp)%n;

	if(_memory.size()!=3)	return false;
	_memory.push_back($N_v);
	return true;
}

/*
_memory[0]:_memory.push_back($T_1);
_memory[1]:_memory.push_back($T_2);
_memory[2]:_memory.push_back($T_2_);
_memory[3]:_memory.push_back($N_v);
*/
bool 
Verifier::gen_c(const VerSignature& verSig, const IsrKey& isrKey)
{
	if(_memory.size()!=4){
		cerr<<"Wrong Size of memory!!"<<endl;
		return false;
	} 
	string _key,_c;

	//H((n||g||g1||h||R0||R1||S||Z||Gamma||gamma||rho)||zeta||(T_1||T_2)||Nv||($T1||$T2||$T'2||$Nv)||n_v)
	
	// issuer PK
	_key+=isrKey.get_n().get_str();
	_key+=isrKey.get_g().get_str();
	_key+=isrKey.get_g1().get_str();
	_key+=isrKey.get_h().get_str();
	_key+=isrKey.get_R0().get_str();
	_key+=isrKey.get_R1().get_str();
	_key+=isrKey.get_S().get_str();
	_key+=isrKey.get_Z().get_str();
	_key+=isrKey.get_Gamma().get_str();
	_key+=isrKey.get_gamma().get_str();
	_key+=isrKey.get_rho().get_str();
	//cout<<"_key in ver:"<<_key<<endl<<endl;
	//verSig
	_key+=verSig.get_zeta().get_str();
	_key+=verSig.get_T_1().get_str();
	_key+=verSig.get_T_2().get_str();
	_key+=verSig.get_N_v().get_str();

	//noise
	_key+=_memory[0].get_str();
	//cout<<"$T_1 : "<<_memory[0].get_str()<<endl<<endl;
	_key+=_memory[1].get_str();
	//cout<<"$T_2 : "<<_memory[1].get_str()<<endl<<endl;
	_key+=_memory[2].get_str();
	//cout<<"$T_2_ : "<<_memory[2].get_str()<<endl<<endl;
	//TPM
	_key+=_memory[3].get_str();
	//cout<<"$N_v : "<<_memory[3].get_str()<<endl<<endl;
	_key+=getNunce().get_str();
	_key=myStr2Int(_hash(_key),16).get_str(16);//_key=_hash(_key);
	_key+=verSig.get_n_t().get_str();
    	_key=_hash(_key);
    	_key+=verSig.get_msg();
    	_memory.push_back(mpz_class(_hash(_key),16));
    	return true;

}
