#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <cmath>
#include "util.h"
#include "scrtPrmt.h"
#include "issuer.h"

using namespace std;

void 
IsrKey::keyGeneration()
{
    //for debug
	cout << "Issuer's public key generating ..." << endl << endl;
	
	//generate p,q
	
	//p=nBitsSafePrimeGen(RSA_SIZE/2);
	//q=nBitsSafePrimeGen(RSA_SIZE/2);
	p=nBitsPrimeGen(RSA_SIZE/2);
	q=nBitsPrimeGen(RSA_SIZE/2);
	n=p*q;

	/*while(pow(2,RSA_SIZE-1)>=n){
		cout<<"Loop Here!"<<endl;
		p=nBitsPrimeGen(RSA_SIZE/2);
		p=nBitsPrimeGen(RSA_SIZE/2);
		n=p*q;
	}*/
	//generate g1
	g1=getQRGen(p,q);
	mpz_class rgQR=(p-1)*(q-1)/4;
        
	//generate g,h,S,Z,R0,R1
	mpz_class x_0,x_1,x_z,x_s,x_h,x_g;

	x_0=myRNG.get_z_range(rgQR);
	x_1=myRNG.get_z_range(rgQR);
	x_z=myRNG.get_z_range(rgQR);
	x_s=myRNG.get_z_range(rgQR);
	x_h=myRNG.get_z_range(rgQR);
	x_g=myRNG.get_z_range(rgQR);

	mpz_powm(g.get_mpz_t(),g1.get_mpz_t(),x_g.get_mpz_t(),n.get_mpz_t());
	mpz_powm(h.get_mpz_t(),g1.get_mpz_t(),x_h.get_mpz_t(),n.get_mpz_t());
	mpz_powm(S.get_mpz_t(),h.get_mpz_t(),x_s.get_mpz_t(),n.get_mpz_t());
	mpz_powm(Z.get_mpz_t(),h.get_mpz_t(),x_z.get_mpz_t(),n.get_mpz_t());
	mpz_powm(R0.get_mpz_t(),S.get_mpz_t(),x_0.get_mpz_t(),n.get_mpz_t());
	mpz_powm(R1.get_mpz_t(),S.get_mpz_t(),x_1.get_mpz_t(),n.get_mpz_t());	
	//generate Gamma, gamma, rho

        mpz_class tmp,tmpPwr;
        do{
	//Gamma=nBitsPrimeGen(GM_SIZE);
	rho=nBitsPrimeGen(RHO_SIZE);
	/*mpz_mod(tmp.get_mpz_t(),Gamma.get_mpz_t(),rho.get_mpz_t());
	cout<<hex<<tmp<<endl;*/
	Gamma=myRNG.get_z_bits(GM_SIZE-RHO_SIZE)*rho+1;
	}while(mpz_probab_prime_p(Gamma.get_mpz_t(),25)==0);

	do{
	tmp=myRNG.get_z_range(Gamma);
	tmpPwr=(Gamma-1)/rho;
	mpz_powm(gamma.get_mpz_t(),tmp.get_mpz_t(),tmpPwr.get_mpz_t(),Gamma.get_mpz_t());
	}while(gamma==0);
/*	
       cout<<"Key checked."<<endl;
       cout<<"Public key:"<<endl
           <<"n: "<<hex<<n<<endl
           <<"g': "<<hex<<g1<<endl
           <<"g: "<<hex<<g<<endl
           <<"h: "<<hex<<h<<endl
           <<"S: "<<hex<<S<<endl
           <<"Z: "<<hex<<Z<<endl
           <<"R0: "<<hex<<R0<<endl
           <<"R1: "<<hex<<R1<<endl
           <<"Gamma: "<<hex<<Gamma
           <<endl<<"rho: "<<hex<<rho
           <<endl<<"gamma: "<<hex<<gamma<<endl;
*/
}

void
IsrProof::proofGeneration()
{}

/*******************************************************/
/*   class Issuer member functions for Join Protocol   */
/*******************************************************/
void 
Issuer::joinSetPseudo(const mpz_class& u, const mpz_class& n)
{
    _memory.push_back(u);  // pseudoU
    _memory.push_back(n);  // pseudoN
}

bool 
Issuer::joinCheckRogueList()
{
    mpz_class baseForN;  // compute itself or from verifier
    mpz_class base = myStr2Int(_hash("1" + _basename), 16);  // _hash_GM !!!!
    mpz_class exp = (_key.get_Gamma() - 1) / _key.get_rho();
    mpz_powm(baseForN.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), _key.get_Gamma().get_mpz_t());

    mpz_class pow_f;
    if (F_SIZE <= 1024) pow_f = pow(2, (int)F_SIZE);
    else mpz_ui_pow_ui(pow_f.get_mpz_t(), 2, F_SIZE);

    for (size_t i = 0; i < _blackList.size(); ++i) {
        mpz_class f0 = _blackList[i] -> get_f0();
        mpz_class f1 = _blackList[i] -> get_f1();
        mpz_class f = f0 + f1 * pow_f;
        mpz_class nRogue;
        mpz_powm(nRogue.get_mpz_t(), baseForN.get_mpz_t(), f.get_mpz_t(), _key.get_Gamma().get_mpz_t());
        if (nRogue == _memory[1]) return false;
    }
    return true;
}
    
string 
Issuer::joinZKPPriMsgNi2Host()
{ 
    mpz_class ni = nBitsGen(H_SIZE);
    _memory.push_back(ni);
    return ni.get_str(16);
}

bool 
Issuer::joinZKPPriMsgVerify(const JoinSMsg& sMsg, const mpz_class& stigma)
{
    mpz_class uHat, u, u1, u2, u3;
    mpz_class cNumInv = -1 * myStr2Int(sMsg.get_c(), 16);
    mpz_powm(u.get_mpz_t(), _memory[0].get_mpz_t(), cNumInv.get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(u1.get_mpz_t(), _key.get_R0().get_mpz_t(), sMsg.get_f0().get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(u2.get_mpz_t(), _key.get_R1().get_mpz_t(), sMsg.get_f1().get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(u3.get_mpz_t(), _key.get_S().get_mpz_t(), sMsg.get_v().get_mpz_t(), _key.get_n().get_mpz_t());
    u *= u1 * u2 * u3;
    mpz_mod(uHat.get_mpz_t(), u.get_mpz_t(), _key.get_n().get_mpz_t());
    
    mpz_class nHat, n, n1, sf;
    mpz_powm(n.get_mpz_t(), _memory[1].get_mpz_t(), cNumInv.get_mpz_t(), _key.get_Gamma().get_mpz_t());
    if (F_SIZE <= 1024) sf = pow(2, (int)F_SIZE);
    else mpz_ui_pow_ui(sf.get_mpz_t(), 2, F_SIZE);
    sf = sMsg.get_f0() + sf * sMsg.get_f1();
    mpz_powm(n1.get_mpz_t(), stigma.get_mpz_t(), sf.get_mpz_t(), _key.get_Gamma().get_mpz_t());
    n *= n1;
    mpz_mod(nHat.get_mpz_t(), n.get_mpz_t(), _key.get_Gamma().get_mpz_t());

    string str = _key.get_n().get_str(16) + _key.get_R0().get_str(16) + _key.get_R1().get_str(16) + _key.get_S().get_str(16)
                 + _memory[0].get_str(16) + _memory[1].get_str(16) + uHat.get_str(16) + nHat.get_str(16) + _memory[2].get_str(16);
    if (sMsg.get_c() != _hash(_hash(str) + sMsg.get_nt())) {
        cerr << "The hash value c is different!!" << endl;
        return false;
    }

    if (!isInCorrectRange(myStr2Int(sMsg.get_c(), 16), (int)H_SIZE)) {
        cerr << "The hash value c is not in the correct range!!" << endl;
        return false;
    }
    if (!isInCorrectRange(sMsg.get_f0(), (int)(F_SIZE + ZKP_SIZE + H_SIZE + 1))) {
        cerr << "The pseudo private message sf0 is not in the correct range!!" << endl;
        return false;
    }
    if (!isInCorrectRange(sMsg.get_f1(), (int)(F_SIZE + ZKP_SIZE + H_SIZE + 1))) {
        cerr << "The pseudo private message sf1 is not in the correct range!!" << endl;
        return false;
    }
    if (!isInCorrectRange(sMsg.get_v(), (int)(RSA_SIZE + 2 * ZKP_SIZE + H_SIZE + 1))) {
        cerr << "The pseudo private message sv1 is not in the correct range!!" << endl;
        return false;
    }

    return true;
}

void
Issuer::joinZKPSgntrACrtSgntr(JoinSgntrA& sgntrA, const mpz_class& nh)
{
    mpz_class v2;
    if (V_SIZE - 1 <= 1024) v2 = pow(2, (int)(V_SIZE - 1));
    else mpz_ui_pow_ui(v2.get_mpz_t(), 2, V_SIZE - 1);
    v2 = nBitsGen(V_SIZE - 1) + v2;

    mpz_class e, cmp, range;
    if (E_SIZE <= 1024) cmp = pow(2, (int)E_SIZE - 1);
    else mpz_ui_pow_ui(cmp.get_mpz_t(), 2, E_SIZE - 1);
    if (E1_SIZE <= 1024) range = pow(2, (int)E1_SIZE - 1);
    else mpz_ui_pow_ui(range.get_mpz_t(), 2, E1_SIZE - 1);
    do {
        mpz_class tmp = cmp + myRNG.get_z_range(range);
        mpz_nextprime(e.get_mpz_t(), tmp.get_mpz_t());
    } while (e < cmp || e > cmp + range);

    mpz_class a, a1, a2, a3;
    mpz_class eInv;
	mpz_class phiN = (_key.p - 1) * (_key.q - 1) / 4;
    mpz_invert(eInv.get_mpz_t(), e.get_mpz_t(), phiN.get_mpz_t()); 
    mpz_class eInvNeg = -1 * eInv;
    mpz_class eInvNegV2 = v2 * eInvNeg;
    mpz_powm(a1.get_mpz_t(), _key.get_Z().get_mpz_t(), eInv.get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(a2.get_mpz_t(), _memory[0].get_mpz_t(), eInvNeg.get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(a3.get_mpz_t(), _key.get_S().get_mpz_t(), eInvNegV2.get_mpz_t(), _key.get_n().get_mpz_t());
    a = a1 * a2 * a3;
    mpz_mod(a.get_mpz_t(), a.get_mpz_t(), _key.get_n().get_mpz_t());

	mpz_class phiN1 = (_key.p - 1) * (_key.q - 1) / 4;
    mpz_class re = myRNG.get_z_range(phiN1);

    mpz_class aTilt;
    mpz_class reNeg = -1 * re;
    mpz_class reNegV2 = v2 * reNeg;
    mpz_powm(a1.get_mpz_t(), _key.get_Z().get_mpz_t(), re.get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(a2.get_mpz_t(), _memory[0].get_mpz_t(), reNeg.get_mpz_t(), _key.get_n().get_mpz_t());
    mpz_powm(a3.get_mpz_t(), _key.get_S().get_mpz_t(), reNegV2.get_mpz_t(), _key.get_n().get_mpz_t());
    aTilt = a1 * a2 * a3;
    mpz_mod(aTilt.get_mpz_t(), aTilt.get_mpz_t(), _key.get_n().get_mpz_t());

    string c1 = _key.get_n().get_str(16) + _key.get_Z().get_str(16) + _key.get_S().get_str(16)
                 + _memory[0].get_str(16) + v2.get_str(16) + a.get_str(16) + aTilt.get_str(16) + nh.get_str(16);
    c1 = _hash(c1);

    mpz_class se;
    mpz_class base = re - myStr2Int(c1, 16) * eInv;
    mpz_mod(se.get_mpz_t(), base.get_mpz_t(), phiN1.get_mpz_t());

    sgntrA = JoinSgntrA(c1, se, a, e, v2);
}

bool
Issuer::reset()
{
    _memory.clear();
    return true;
}
