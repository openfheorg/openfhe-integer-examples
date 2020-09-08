/* PALISADE C++ program implements the Rabin-Karp method for string matching using
 * encrypted computation
 * plaintext version of this code comes from 
 * https://www.sanfoundry.com/cpp-program-implement-rabin-karp-method-for-string-matching
 * author David Bruce Cousins@dualitytech.com

 */


#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "debug.h"
#include "palisade.h"
using namespace std;
using namespace lbcrypto;

//data types we will need
using CT = Ciphertext<DCRTPoly> ; //ciphertext
using PT = Plaintext ; //plaintext
using vecCT = vector<CT>; //vector of ciphertexts
using vecPT = vector<PT>; //vector of plaintexts
using vecInt = vector<int64_t>; // vector of ints
using vecChar = vector<char>; // vector of characters

// d is the number of characters in input alphabet
const int d = 256;
     
/*  pat  -> pattern
	txt  -> text
	p    -> A prime number
*/
     
void get_input_from_term(vecChar& a) {
  string cstr;
  cin.ignore(numeric_limits<streamsize>::max(),'\n'); //flushes buffer
  std::getline(std::cin, cstr);
  cout <<"Pattern is `"<<cstr<<"'"<<endl;    
  for(auto c: cstr) {
	a.push_back(c);
  }
  cout <<"Pattern is "<<a.size()<<" characters"<<endl;  
  return;
}
     
void get_input_from_file(vecChar& a, string fname) {
  char c;

  ifstream in_file;
  in_file.open(fname);
  if (!in_file) {
	cerr << "Can't open file for input: "<<fname;
	exit(-1); //error exit
  }
  
  while (in_file >> c) {
	a.push_back(c);
  }
  cout <<"Read "<<a.size()<<" characters"<<endl;
  in_file.close();
  return;
}
     
     
vecInt search(vecChar &pat, vecChar &txt, int ps) {
  long p(ps);
  DEBUG_FLAG(false);
  int M = pat.size();
  DEBUGEXP(M);
  int N = txt.size();
  DEBUGEXP(N);
  int i, j;
  long ph = 0;  // hash value for pattern
  long th = 0; // hash value for txt
  long h = 1;

  int nfound = 0;
     
  // The value of h would be "pow(d, M-1)%p"
  for (i = 0; i < M-1; i++) {
	h = (h*d)%p;
	DEBUGEXP(h);
  }
  DEBUG(" hfinal: "<<h);

  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
	ph = (d * ph + pat[i]) % p;
	th = (d * th + txt[i]) % p;
  }
  DEBUG(" initial ph: "<<ph);
  DEBUG(" initial th: "<<th);
  vecInt pres(0);
  // Slide the pattern over text one by one
  for (i = 0; i <= N - M; i++) {
	
	// Check the hash values of current window of text and pattern
	// If the hash values match then only check for characters on by one
	pres.push_back((ph-th)%p);
	if ( ph == th )	{
	  /* Check for characters one by one */
	  for (j = 0; j < M; j++) {
		if (txt[i + j] != pat[j])
		  break;
	  }
	  if (j == M) { // if ph == t and pat[0...M-1] = txt[i, i+1, ...i+M-1]

		cout<<"Pattern found at index "<< i << endl;
		nfound++;
	  }
	}
     
	// Calculate hash value for next window of text: Remove leading digit,
	// add trailing digit
	if ( i < N - M ) {
	  th = (d * (th - txt[i] * h) + txt[i + M]) % p;

	  // We might get negative value of t, converting it to positive
	  if (th < 0) {
		th = (th + p);
	  }

	  //cout<<" "<<th;
	}
  } //end for
  //cout<<endl;
  cout<<"total occurances " <<nfound<<endl;
  return pres;
}
     

CT encrypt_repeated_integer(CryptoContext<DCRTPoly> &cc, LPPublicKey<DCRTPoly> &pk,  int64_t in, size_t n){
  
  vecInt v_in(0);
  for (auto i = 0; i < n; i++){
	v_in.push_back(in);
  }
  PT pt= cc->MakePackedPlaintext(v_in);
  CT ct = cc->Encrypt(pk, pt);

  return ct;
}

CT encMultD(CryptoContext<DCRTPoly> &cc, CT in){
  if (d !=256){
	cout <<"error d not 256"<<endl;
	exit(-1);
  }
  auto tmp(in);
  for (auto i = 0; i< 8; i++ ){
	tmp = cc->EvalAdd(tmp, tmp);
  }
  
  return(tmp);
}
     
vecCT encrypted_search(CryptoContext<DCRTPoly> &cc,  LPPublicKey<DCRTPoly> &pk, LPPrivateKey<DCRTPoly> &sk, vecCT &epat, vecCT &etxt, int ps) {

  long p(ps);
  DEBUG_FLAG(false);
  int M = epat.size();
  DEBUGEXP(M);
  int N = etxt.size();
  DEBUGEXP(N);
  int i, j;

  PT dummy;
  
  size_t nrep(1);
  DEBUG("encrypting small ct");
  CT phct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for pattern
  CT thct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for txt

  int nfound = 0;
  DEBUG("encrypting hct");     
  // The value of h would be "pow(d, M-1)%p"
  long h = 1;
  for (i = 0; i < M-1; i++) {
	h = (h*d)%p;
  }
  CT hct = encrypt_repeated_integer(cc, pk, h, nrep);  // encrypted h
  //cc->Decrypt(sk, hct, &dummy);
  //cout<<" hct: "<<dummy<<endl;

  DEBUG("encrypting first hashes" );     
  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
	auto tmp = encMultD(cc, phct);	
	phct = cc->EvalAdd(tmp, epat[i]);

	tmp = encMultD(cc, thct);
	thct = cc->EvalAdd(tmp, etxt[i]);
  }
  //cc->Decrypt(sk, phct, &dummy);
  //cout<<" initial phct: "<<dummy<<endl;
  //cc->Decrypt(sk, thct, &dummy);
  //cout<<" initial thct: "<<dummy<<endl;

  vecCT eres(0);
  // Slide the pattern over text one by one
  DEBUG("sliding" );     
  for (i = 0; i <= N - M; i++) {
	cout<<i<< '\r'<<flush;
	
	// Check the hash values of current window of text and pattern
	// If the hash values match then only check for characters on by one
	// subtract the two hashes, zero is equality
	DEBUG("sub" );     
	eres.push_back(cc->EvalSub(phct, thct));
     
	// Calculate hash value for next window of text: Remove leading digit,
	// add trailing digit
	if ( i < N - M ) {
	  DEBUG("rehash" );     
	  //th = (d * (th - txt[i] * h) + txt[i + M]) % p;
	  //cout <<"thct depth before "<<thct->GetDepth()<<endl;

	  auto tmp = encMultD(cc,
						  cc->EvalSub(thct,
									  cc->EvalMult(etxt[i], hct)
									  )
						  );
	  thct = cc->EvalAdd(tmp, etxt[i+M] );

	  cc->Decrypt(sk, thct, &dummy);
	  auto test = dummy->GetPackedValue();
	  if (test[1] != 0) {
		cout<<"overflow!!"<<endl;
		exit(-1);
	  }
	}

  } //end for
  return eres;
}
     
int main()
{
  vecChar txt;
  vecChar pat;
  string infilename;

  cout<<sizeof(int)<<endl;
  cout<<sizeof(long)<<endl;
  
  cout<<"Enter file for Text:";
  //cin >> infilename;
  //infilename = "data/alice.txt";
  infilename = "data/warandpeace.txt";
  get_input_from_file(txt, infilename);

  //cout<<"Enter text size:";
  unsigned int textSize(0);
  //cin>> textSize;
  textSize = 64;
  cout << "Limiting search to "<<textSize<< " characters"<<endl;
  
  txt.resize(textSize);
  
  cout<<"Enter Pattern to Search:";
  //get_input_from_term(pat);
  pat = {'T', 'o', 'l', 's', 't', 'o', 'y'};
  
  int p = 786433; //plaintext prime modulus
  //int p = 65537;

  cout<<"p "<<p<<endl;
  TIC(auto t1);

  auto presult = search(pat, txt, p);
  auto plain_time_ms = TOC_MS(t1);
  cout<< "Plaintext execution time "<<plain_time_ms<<" mSec."<<endl;

  cout <<"setting up BFV RNS crypto system"<<endl;

  uint32_t plaintextModulus = p;
  //  uint32_t multDepth = 32;  //n search char - 4
    uint32_t multDepth = 16; 
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
	CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
		plaintextModulus, securityLevel, sigma, 0, multDepth, 0, OPTIMIZED);

	
  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  cout<<"Step 2 - Key Generation"<<endl;
  
  // Initialize Public Key Containers
  // Generate a public/private key pair
  auto keyPair = cc->KeyGen();
  
  // Generate the relinearization key
  cc->EvalMultKeyGen(keyPair.secretKey);

  // note we do not use rotation in this example so we don't need rotation keys
  // but make them anyway 
  // Generate the rotation evaluation keys
  cc->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2}); 

  cout<<"Step 3 - Encryption"<<endl;  


  cout<<"Step 3.1 - Encrypt pattern"<<endl;  
  //encrypt the pattern
  vecInt vin(0);
  vecCT epat(0);
  unsigned int j(0);
  for (auto ch: pat) {
	cout<<j<< '\r'<<flush;
	j++;
	vin.push_back(ch);
	PT pt= cc->MakePackedPlaintext(vin);
	vin.clear();
	CT ct = cc->Encrypt(keyPair.publicKey, pt);
	epat.push_back(ct);
  }	

  //encrypt the text
  auto ringsize = cc->GetRingDimension();
  cout << "ringsize = "<<ringsize << endl;
  cout << "txt size = "<<txt.size() << endl;
  unsigned int nbatch = int(ceil(float(txt.size())/float(ringsize)));
  cout << "can store "<<nbatch <<" batches in the ct"<<endl;
	
  cout<<"Step 3.2 - Encrypt text"<<endl;  
  vecCT etxt(0);
  auto pt_len(0);
  for (auto i = 0; i < txt.size(); i++) {
	cout<<i<< '\r'<<flush;

	vin.push_back(txt[i]);
	Plaintext pt= cc->MakePackedPlaintext(vin);
	pt_len = pt->GetLength();
	vin.clear();
	CT ct = cc->Encrypt(keyPair.publicKey, pt);
	etxt.push_back(ct);
  }	
  cout<<"Step 4 - Encrypted string search"<<endl;  

  TIC(auto t2);
  //secret key only for debug. remove it after
  vecCT eresult = encrypted_search(cc, keyPair.publicKey, keyPair.secretKey, epat, etxt, p);
  auto encrypted_time_ms = TOC_MS(t2);
		  cout<< "Encrypted execution time "<<encrypted_time_ms<<" mSec."<<endl;  

  


  vecPT vecResult(0);
  for (auto e_itr:eresult){
	PT ptresult;  
	cc->Decrypt(keyPair.secretKey, e_itr, &ptresult);
	ptresult->SetLength(pt_len);
	vecResult.push_back(ptresult);
  }

  int i(0);
  int nfound(0);
  for (auto val: vecResult) {
	auto unpackedVal = val->GetPackedValue();
	if (unpackedVal[0] == 0) {
	  cout<<"Pattern found at index "<< i << endl;
	  nfound++;
	}
	i++;
  }
  cout<<"total occurances "<<nfound<<endl;
  //  cout<<"encrypted Result "<<vecResult << endl;
  //cout<<"plaintext Result "<<presult << endl;

  //for (auto i = 0; i < vecResult.size(); i++){
  //	cout<< vecResult[i] << " " << presult[i]<<endl;
  //}

  return 0;
}
