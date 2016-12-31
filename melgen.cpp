#include "melcrypt.h"
#include "config.h"

int main() {
//	Create Elliptic Curve Keys Objects
	CryptoPP::AutoSeededRandomPool prng;	
	CryptoPP::ECIES < CryptoPP::ECP >::PrivateKey d0;    
	CryptoPP::ECIES < CryptoPP::ECP >::PublicKey e0;
	
	string kname;

//	Generate Elliptic Curve Keys	
	d0.Initialize (prng, CryptoPP::ASN1::brainpoolP512r1());    
	d0.MakePublicKey (e0);

//	Calculate sha1sum of Elliptic Curve Keys 		
	ShaPriv(kname,d0);
	cout<<kname<<endl;
	kname.append(".priv");
	cout<<kname<<endl;

//	Validate  and save private key 
	if (false == d0.Validate (prng, 3)){        
     cout<<"Private key validation failed"<<endl;
     return 1;      
	}
    else SavePriv64(kname,d0);

	kname.erase (kname.end()-5, kname.end());
	kname.append(".pub");
	cout<<kname<<endl;

//	Validate  and save public key     
	if (false == e0.Validate (prng, 3)){        
         cout<<"Public key validation failed"<<endl;
         return 1; 
	}
	else SavePub64(kname,e0);
	
	return 0;

}
