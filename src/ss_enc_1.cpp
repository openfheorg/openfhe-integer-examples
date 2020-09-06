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
     
     
void search(vecChar &pat, vecChar &txt, int ps) {
  long p(ps);
  DEBUG_FLAG(true);
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
  }
  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
	ph = (d * ph + pat[i]) % p;
	th = (d * th + txt[i]) % p;
  }
     
  // Slide the pattern over text one by one
  for (i = 0; i <= N - M; i++) {
	
	// Check the hash values of current window of text and pattern
	// If the hash values match then only check for characters on by one
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
	}
  } //end for
  cout<<"total occurances " <<nfound<<endl;
}
     

CT encrypt_repeated_integer(CryptoContext<DCRTPoly> &cc, LPPublicKey<DCRTPoly> &pk, int64_t in, size_t n){
  
  vecInt v_in(0);
  for (auto i = 0; i < n; i++){
	v_in.push_back(0);
  }
  PT pt= cc->MakePackedPlaintext(v_in);
  CT ct = cc->Encrypt(pk, pt);
  return ct;
}	
     
vecCT encrypted_search(CryptoContext<DCRTPoly> &cc,  LPPublicKey<DCRTPoly> &pk, vecCT &epat, vecCT &etxt) {
  DEBUG_FLAG(true);
  int M = epat.size();
  DEBUGEXP(M);
  int N = etxt.size();
  DEBUGEXP(N);
  int i, j;

  size_t nrep(1);

  CT phct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for pattern
  CT thct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for txt
  CT hct = encrypt_repeated_integer(cc, pk, 1, nrep);  // encrypted h
  CT dct = encrypt_repeated_integer(cc, pk, d, nrep);  // encrypted d

  int nfound = 0;
     
  // The value of h would be "pow(d, M-1)%p"
  for (i = 0; i < M-1; i++) {
	hct = cc->ComposedEvalMult(hct, dct);
  }

  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
	auto tmp = cc->EvalAdd(phct,epat[i]);
	phct = cc->ComposedEvalMult(tmp, dct);
	tmp = cc->EvalAdd(thct,etxt[i]);
	thct = cc->ComposedEvalMult(tmp, dct);
  }

  vecCT eresult(0);
  // Slide the pattern over text one by one
  for (i = 0; i <= N - M; i++) {
	cout<<i<< '\r'<<flush;
	
	// Check the hash values of current window of text and pattern
	// If the hash values match then only check for characters on by one
	// subtract the two hashes, zero is equality

	eresult.push_back(cc->EvalSub(phct, thct));
     
	// Calculate hash value for next window of text: Remove leading digit,
	// add trailing digit
	if ( i < N - M ) {
	  
	  //th = (d * (th - txt[i] * h) + txt[i + M]) % p;
	  thct = cc->EvalAdd(cc->ComposedEvalMult(dct,
											  cc->EvalSub(thct,
														  cc->ComposedEvalMult(etxt[i], hct)
														  )
											  ), etxt[i+M]
						 );
	}
  } //end for
  return eresult;
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

  cout<<"Enter Pattern to Search:";
  get_input_from_term(pat);

  int p = 786433; //plaintext prime modulus

  cout<<"p "<<p<<endl;
  TIC(auto t1);
  search(pat, txt, p);
  auto plain_time_ms = TOC_MS(t1);
  cout<< "Plaintext execution time "<<plain_time_ms<<" mSec."<<endl;

  cout <<"setting up BGV RNS crypto system"<<endl;
  

  uint32_t plaintextModulus = p;
  uint32_t multDepth = 50;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          multDepth, plaintextModulus, securityLevel, sigma, 2, OPTIMIZED, HYBRID, 0, 0, 0, 0, 0, 0, MANUAL);
	
  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  cout<<"Step 2 - Key Generation"<<endl;
  
  // Initialize Public Key Containers
  // Generate a public/private key pair
  auto keyPair = cc->KeyGen();
  
  // Generate the relinearization key
  cc->EvalMultKeyGen(keyPair.secretKey);
  
  cout<<"Step 3 - Encryption"<<endl;  

  auto ringsize = cc->GetRingDimension();
  cout << "ringsize = "<<ringsize << endl;
									 

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
  unsigned int nbatch = ceil(txt.size()/ringsize);
  cout << "can store "<<nbatch <<" batches in the ct"<<endl;
	
  //for now lets only do the first 64 characters

  vecCT etxt(0);
  auto pt_len(0);
  for (auto i = 0; i < 64; i++) {
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
  vecCT eresult = encrypted_search(cc, keyPair.publicKey, epat, etxt);
  auto encrypted_time_ms = TOC_MS(t2);
		  cout<< "Encrypted execution time "<<encrypted_time_ms<<" mSec."<<endl;  

  


  vecPT vecResult(0);
  for (auto e_itr:eresult){
	PT ptresult;  
	cc->Decrypt(keyPair.secretKey, e_itr, &ptresult);
	ptresult->SetLength(pt_len);
	vecResult.push_back(ptresult);
  }

  cout<<"Result "<<vecResult << endl;
  return 0;
}
