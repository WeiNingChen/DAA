#include <iostream>
#include <iomanip>
#include <gmp.h>
#include <gmpxx.h>
#include "protocol.h"
#include "message.h"
#include "util.h"
#include "scrtPrmt.h"

using namespace std;

/*******************************************************/
/*        class JoinProtocol member functions          */
/*******************************************************/
bool 
JoinProtocol::operator() (Issuer* issuer, Host* host)
{
    cout << "Join protocol is starting..." << endl;

    if (!reset(issuer, host)) {
        cout << "[ERROR] The entities aren't reset!!" << endl;
        return false;
    }
    // Verify PKI with longtermPKI
    mpz_class stigma = host -> joinStigma2TPM(issuer -> getBasename(), issuer -> getPK());    
    if (!(host -> _tpm -> joinCheckStigma(stigma, issuer -> getPK()))) {
        cerr << "[ERROR] The base stigma which the host gave to the TPM isn't computed correctly!!" << endl;
        return false;
    }
    mpz_class pseudoU, pseudoN;
    host -> _tpm -> joinCrtPriMsg(pseudoU, pseudoN, issuer -> getLTPKI(), issuer -> getPK()); // seed, longtermPKI, cnt
    issuer -> joinSetPseudo(pseudoU, pseudoN);
    if (!(issuer -> joinCheckRogueList())) {
        cerr << "[ERROR] The private message is rogue!!" << endl;
        return false;
    }
    if (!joinZKPPriMsgTPM2Issuer(issuer, host, stigma, pseudoU, pseudoN)) { 
        cerr << "[ERROR] The TPM fails to prove to the issuer knowledge of f0, f1 and v'!!" << endl;
        return false;
    }
    else cout << "The TPM prove to the issuer knowledge of f0, f1, v'..." << endl;
    if (!joinZKPSgntrAIssuer2Host(issuer, host, pseudoU)) {
        cerr << "[ERROR] The issuer fails to convince the host that A was correctly computed!!" << endl;
        return false;
    }
    else cout << "The issuer convince to the host that A was correctly computed..." << endl;
    host -> _tpm -> setPriMsg(host -> getSgntrA_v2(), issuer);

    // for debug //
    if (!(host -> _tpm -> checkPriMsgSigntr(host -> _priMsgSgntrs.back(), issuer -> getPK()))) {
        cerr << "[ERROR] Signature is wrong !!!!!!" << endl;
        return false;
    }
    // for debug //
    if (!reset(issuer, host)) {
        cout << "[ERROR] The entities aren't reset!!" << endl;
        return false;
    }
    if(host->_tpm->_issuer==NULL) host->_tpm->_issuer=issuer;
    cout << "Join protocol is finished..." << endl;
    return true;
}

bool 
JoinProtocol::joinZKPPriMsgTPM2Issuer(Issuer* issuer, Host* host, 
        const mpz_class& stigma, const mpz_class& pseudoU, const mpz_class& pseudoN)
{
    mpz_class uTilt, nTilt;
    host -> _tpm -> joinZKPPriMsgCrtRnd(uTilt, nTilt, issuer -> getPK());
    string niRnd = issuer -> joinZKPPriMsgNi2Host();
    string ch = host -> joinZKPPriMsg_ch2TPM(pseudoU, pseudoN, uTilt, nTilt, niRnd, issuer -> getPK());
    JoinSMsg sMsg;
    host -> _tpm -> joinZKPPriMsgPseudoMsg(sMsg, ch);  // sMsg : TPM -> Host -> Issuer
    return issuer -> joinZKPPriMsgVerify(sMsg, stigma);
}

bool 
JoinProtocol::joinZKPSgntrAIssuer2Host(Issuer* issuer, Host* host, const mpz_class& pseudoU)
{
    mpz_class nh = host -> joinZKPSgntrA_nh2Issuer();
    JoinSgntrA sgntrA; 
    issuer -> joinZKPSgntrACrtSgntr(sgntrA, nh);
    if (host -> joinZKPSgntrAVerify(sgntrA, issuer -> getPK(), pseudoU)) return true;
    else return false;
}

bool 
JoinProtocol::reset(Issuer* issuer, Host* host)
{
    if (!(issuer -> reset())) {
        cout << "[ERROR] The issuer isn't reset!!" << endl;
        return false;
    }
    if (!(host -> reset())) {
        cout << "[ERROR] The issuer isn't reset!!" << endl;
        return false;
    }
    if (!(host -> _tpm -> reset())) {
        cout << "[ERROR] The issuer isn't reset!!" << endl;
        return false;
    }
    return true;
}
    
/********************************************************************************************************************/
/********************************************************************************************************************/

bool
SignProtocol::operator()(Host* host, Verifier* ver)
{
    if(!host->genVerSig(NULL, ver, NULL)){
        cout<<"[ERROR] Fail to generate certificate in SignProtocol !!"<<endl;
        return false;
    }
    if(!ver->verifySignature(host->getVerSig(ver),host->_tpm->getIssuer())){
        cout<<"[ERROR] Fail to verify certificate in SignProtocol !!"<<endl;
        return false;
    }
    return true;
}

void
SignProtocol::printVerList()
{
	vector<Verifier*> _v = Verifier::_verifierList;
	size_t i = 0;
	cout << "===========================================" << endl
	     << "=             Verifier List               =" << endl
	     << "===========================================" << endl;
	while(i < _v.size()) {
        cout << "= " << setw(40) << left << _v[i] -> getBasename() << "=" << endl;
		++i;
	}
	cout << "___________________________________________" << endl
	     << "= Total: " << setw(33) << _v.size() << "=" << endl
	     << "===========================================" << endl << endl;
}

void
SignProtocol::printHostList()
{
	vector<Host*> _h = Host::_hostList;
	size_t i = 0;
	cout << "===========================================" << endl
	     << "=               Host List                 =" << endl
	     << "===========================================" << endl;
	while(i < _h.size()) {
        cout << "= " << setw(40) << left << _h[i]->getHostId() <<  "=" << endl;
		++i;
	}
	cout << "___________________________________________" << endl << endl
	     << "= Total: " << setw(33) << _h.size() << "=" << endl
	     << "===========================================" << endl << endl;
}
