#include "melcrypt.h"
#include "config.h"

int main() {

	CryptoPP::AutoSeededRandomPool prng;	
	CryptoPP::ECIES < CryptoPP::ECP >::PrivateKey d0;    
	CryptoPP::ECIES < CryptoPP::ECP >::PublicKey e0;
	
	string kname;
	
	d0.Initialize (prng, CryptoPP::ASN1::brainpoolP512r1());    
	d0.MakePublicKey (e0);
		
	ShaPriv(kname,d0);
	cout<<kname<<endl;
	kname.append(".priv");
	cout<<kname<<endl;
	
	if (false == d0.Validate (prng, 3)){        
     cout<<"Private key validation failed"<<endl;
     return 1;      
	}
    else SavePriv64(kname,d0);

	kname.erase (kname.end()-5, kname.end());
	kname.append(".pub");
	cout<<kname<<endl;
    
	if (false == e0.Validate (prng, 3)){        
         cout<<"Public key validation failed"<<endl;
         return 1; 
	}
	else SavePub64(kname,e0);
	
	return 0;

}
