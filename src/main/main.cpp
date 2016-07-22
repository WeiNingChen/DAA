#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <sstream>
#include <string>
#include "issuer.h"
#include "host.h"
#include "verifier.h"
#include "util.h"

using namespace std;


JoinProtocol join; 
SignProtocol sign;

int main()
{
	initRNG();
	Issuer isr(0);

	Verifier ver1("A");
	Verifier ver2("B");
	Verifier ver3("C");

	cout << "Verifier \"" << ver1.getBasename() << "\" is created!" << endl;
	cout << "Verifier \"" << ver2.getBasename() << "\" is created!" << endl;
	cout << "Verifier \"" << ver3.getBasename() << "\" is created!" << endl << endl;

	Host host1("John");
	Host host2("Mary");
	Host host3("Steve");

	cout << "Host \"" << host1.getHostId() << "\" is created!" << endl;
	cout << "Host \"" << host2.getHostId() << "\" is created!" << endl;
	cout << "Host \"" << host3.getHostId() << "\" is created!" << endl << endl;

	// Join Protocol for host1
	cout << "The TPM in the host \"" << host1.getHostId() << "\" is asking to join by issuer..." << endl;
	if(!join(&isr, &host1)) cout << "Host \"" << host1.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Join successfully!!" << endl << endl;
    host1.printSignature();

	// Join Protocol for host2
	cout << "The TPM in the host \"" << host2.getHostId() << "\" is asking to join by issuer..." << endl;
	if(!join(&isr, &host2)) cout << "Host \"" << host2.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Join successfully!!" << endl << endl;
    host2.printSignature();

	// Join Protocol for host1
	cout << "The TPM in the host \"" << host3.getHostId() << "\" is asking to join by issuer..." << endl;
	if(!join(&isr, &host3)) cout << "Host \"" << host3.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Join successfully!!" << endl << endl;
    host3.printSignature();

	if(host1.addVerifier(&ver1)) 
		cout << "Host \"" << host1.getHostId() << "\" adds verifier " << ver1.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver1.getBasename() << "\" verify host " << host1.getHostId() << "'s certificate..." << endl;
	if(!sign(&host1, &ver1)) 
		cout << "Host \"" << host1.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host1.addVerifier(&ver2)) 
		cout << "Host \"" << host1.getHostId() << "\" adds verifier " << ver2.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver2.getBasename() << "\" verify host " << host1.getHostId() << "'s certificate..." << endl;
	if(!sign(&host1, &ver2)) 
		cout << "Host \"" << host1.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host1.addVerifier(&ver3)) 
		cout << "Host \"" << host1.getHostId() << "\" adds verifier " << ver3.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver3.getBasename() << "\" verify host " << host1.getHostId() << "'s certificate..." << endl;
	if(!sign(&host1, &ver3)) 
		cout << "Host \"" << host1.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host2.addVerifier(&ver1)) 
		cout << "Host \"" << host2.getHostId() << "\" adds verifier " << ver1.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver1.getBasename() << "\" verify host " << host2.getHostId() << "'s certificate..." << endl;
	if(!sign(&host2,&ver1)) 
		cout << "Host \"" << host2.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host2.addVerifier(&ver2)) 
		cout << "Host \"" << host2.getHostId() << "\" adds verifier " << ver2.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver2.getBasename() << "\" verify host " << host2.getHostId() << "'s certificate..." << endl;
	if(!sign(&host2,&ver2)) 
		cout << "Host \"" << host2.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host2.addVerifier(&ver3)) 
		cout << "Host \"" << host2.getHostId() << "\" adds verifier " << ver3.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver3.getBasename() << "\" verify host " << host2.getHostId() << "'s certificate..." << endl;
	if(!sign(&host2,&ver3)) 
		cout << "Host \"" << host2.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host3.addVerifier(&ver1)) 
		cout << "Host \"" << host3.getHostId() << "\" adds verifier " << ver1.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver1.getBasename() << "\" verify host " << host3.getHostId() << "'s certificate..." << endl;
	if(!sign(&host3,&ver1)) 
		cout << "Host \"" << host3.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host3.addVerifier(&ver2)) 
		cout << "Host \"" << host3.getHostId() << "\" adds verifier " << ver2.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver2.getBasename() << "\" verify host " << host3.getHostId() << "'s certificate..." << endl;
	if(!sign(&host3,&ver2)) 
		cout << "Host \"" << host3.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	if(host3.addVerifier(&ver3)) 
		cout << "Host \"" << host3.getHostId() << "\" adds verifier " << ver3.getBasename() << " ..." << endl;
    // Verification
	cout << "Verifier \"" << ver3.getBasename() << "\" verify host " << host3.getHostId() << "'s certificate..." << endl;
	if(!sign(&host3,&ver3)) 
		cout << "Host \"" << host3.getHostId() << "\" is rejected!!" << endl << endl;
	else cout << "Verify successfully!!" << endl << endl;

	host1.printVer();
	host2.printVer();
	host3.printVer();

	sign.printVerList();
	sign.printHostList();
}
