/* PALISADE C++ program implements the Rabin-Karp method for string
 * matching using encrypted computation with SIMD batching
 * plaintext version of this code comes from 
 * https://www.sanfoundry.com/cpp-program-implement-rabin-karp-method-for-string-matching
 * author David Bruce Cousins@dualitytech.com

 */


#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
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


// function to get string input from terminal and return as vector of char
void get_input_from_term(vecChar& a) {
  string cstr;
  cin.ignore(numeric_limits<streamsize>::max(),'\n'); //flushes buffer
  cin >> ws; //discards white space
  std::getline(std::cin, cstr);
  cout <<"Pattern is `"<<cstr<<"'"<<endl;    
  for(auto c: cstr) {
	a.push_back(c);
  }
  cout <<"Pattern is "<<a.size()<<" characters"<<endl;  
  return;
}

// function to read text from a file and return as vector of char
void get_input_from_file(vecChar& a, string fname) {
  char c;

  ifstream in_file;
  in_file.open(fname);
  if (!in_file) {
	cerr << "Can't open file for input: "<<fname<<endl;
	exit(-1); //error exit
  }
  
  while (in_file >> c) {
	a.push_back(c);
  }
  cout <<"Read "<<a.size()<<" characters"<<endl;
  in_file.close();
  return;
}
     
// plaintext string search of pat within txt, with modulus of ps     
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
	if ( ph == th )	{
	  /* Check for characters one by one */
	  for (j = 0; j < M; j++) {
		if (txt[i + j] != pat[j])
		  break;
	  }
	  if (j == M) { // if ph == t and pat[0...M-1] = txt[i, i+1, ...i+M-1]

		//cout<<"Pattern found at index "<< i << endl;
		pres.push_back(i);
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
  cout<<"total occurences " <<nfound<<endl;
  return pres;
}
     
// helper function to encrypt an integer repeatedly into a packed plaintext
// and encrypt it
CT encrypt_repeated_integer(CryptoContext<DCRTPoly> &cc, LPPublicKey<DCRTPoly> &pk,  int64_t in, size_t n){
  
  vecInt v_in(n, in);
  PT pt= cc->MakePackedPlaintext(v_in);
  CT ct = cc->Encrypt(pk, pt);

  return ct;
}

// helper function to multiply by constant 256 using binary tree addition
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

//SIMD encrypted search
vecCT encrypted_search(CryptoContext<DCRTPoly> &cc,  LPPublicKey<DCRTPoly> &pk,  vecCT &epat, vecCT &etxt, int ps) {

  long p(ps);
  DEBUG_FLAG(false);
  int M = epat.size();
  DEBUGEXP(M);
  int N = etxt.size();
  DEBUGEXP(N);
  int i;

  PT dummy;
  
  size_t nrep(cc->GetRingDimension());
  DEBUG("encrypting small ct");
  CT phct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for pattern
  CT thct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for txt

  CT dhct = encrypt_repeated_integer(cc, pk, d, nrep);  // d

  DEBUG("encrypting hct");     
  // The value of h would be "pow(d, M-1)%p"
  long h = 1;
  for (i = 0; i < M-1; i++) {
	h = (h*d)%p;
  }
  CT hct = encrypt_repeated_integer(cc, pk, h, nrep);  // encrypted h

  DEBUG("encrypting first hashes" );     
  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
	auto tmp = encMultD(cc, phct);	
	phct = cc->EvalAdd(tmp, epat[i]);

	tmp = encMultD(cc, thct);
	thct = cc->EvalAdd(tmp, etxt[i]);
  }

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
	  auto tmp = encMultD(cc,
						  cc->EvalSub(thct,
									  cc->EvalMult(etxt[i], hct)
									  )
						  );

	  thct = cc->EvalAdd(tmp, etxt[i+M] );
	}

  } //end for
  return eres;
}
     
int main()
{
  vecChar txt;
  vecChar pat;
  string infilename;

  //cout<<"Enter file for Text:";
  //cin >> infilename;
  infilename = "data/annakarenina.txt";
  get_input_from_file(txt, infilename);

  //cout<<"Enter buffer size:";
  unsigned int maxNBatches(0);
  unsigned int minNBatches(0);
  //cin>> maxNBatches;
  maxNBatches = 32;
  minNBatches = 10;
  cout << "batching to "<<maxNBatches<< " characters max"<<endl;

  //cout<<"Enter Pattern to Search:";
  
  //get_input_from_term(pat);
  pat = {'A', 'n', 'n', 'a'};

  int p = 786433; //plaintext prime modulus
  //int p = 65537; // use this to show core dump

  cout<<"p "<<p<<endl;
  TIC(auto t1);

  auto presult = search(pat, txt, p);
  auto plain_time_ms = TOC_MS(t1);
  cout<< "Plaintext execution time "<<plain_time_ms<<" mSec."<<endl;

  cout <<"setting up BFV RNS crypto system"<<endl;

  uint32_t plaintextModulus = p;
  uint32_t multDepth = 32; //works for 32 batches

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
  //cc->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2}); 

  cout<<"Step 3 - Encryption"<<endl;  

  cout<<"Step 3.1 - Encrypt text"<<endl;  

  //encrypt the text
  auto ringsize = cc->GetRingDimension();
  cout << "Given ringsize = "<<ringsize << endl;
  cout << "and text size = "<<txt.size() << endl;
  unsigned int nbatchEst = int(ceil(float(txt.size())/float(ringsize)));
  cout << "We can store approximately "<<nbatchEst <<" batches in the CT"<<endl;

  //need to encrypt the text in batches, each one consists of
  //nbatch points. the next batch starts at nbatch-M 
  //so each CT in the vecCT has ringsize entries.
  // vecCT[0] has characters {0, nbatch-M, 2(nbatch-M) etc..}
  // vecCT[1] has characters {1, 1+(nbatch-M), 1+2(nbatch-M) etc..}
  cout << "Adjusting number of batches to account for pattern overlap"<<endl;
  bool done(false);
  auto nbatch = max(minNBatches, nbatchEst);
  auto M(pat.size());

  //offset into text corresponding to start of each ring element
  vecInt offset(0); 
  size_t largestIx(0);
  while (!done){
    //try this combination of nbatch and M and adjust till it fits
    offset.clear();
    for(usint bat = 0; bat < ringsize; bat++){
      offset.push_back(bat*(nbatch-M+1));
    }

    largestIx= offset[offset.size()-1]+(nbatch-1);

    if (largestIx >= txt.size()){
      done = true;
    } else {
      nbatch++;
      cout<<"increasing batch size to "<<nbatch<<endl;
    }
  }

  
  if (nbatch > maxNBatches) {
	cout<<"have to limit number of batches to "<<maxNBatches<<endl;
	nbatch = maxNBatches;
	if (largestIx+1 < txt.size()){
	  cout<<"have to limit text size to "<<largestIx+1<<endl;
	  txt.resize(largestIx+1);
	}
  }

  vecCT etxt(0);
  auto pt_len(0);  
  
  vecInt vin(0);
  for (usint i = 0; i < nbatch; i++) {
    cout<<i<< '\r'<<flush;
    //build a vector out of the batches 
    for(usint bat = 0; bat < ringsize; bat++){
      if (i+(unsigned)offset[bat] >= txt.size()) {
        vin.push_back('\0'); //null terminate
      } else {
        vin.push_back(txt[i+offset[bat]]);
      }
    }
    Plaintext pt= cc->MakePackedPlaintext(vin);
    pt_len = pt->GetLength();
    vin.clear();
    CT ct = cc->Encrypt(keyPair.publicKey, pt);
    etxt.push_back(ct);
  }
  cout<<"encrypted "<<etxt.size()<<" batches"<<endl;

  cout<<"Step 3.2 - Encrypt pattern"<<endl;  
  //encrypt the pattern
  // we copy the pattern over the entire ring
  vecCT epat(0);
  unsigned int j(0);
  for (auto ch: pat) {
	cout<<j<< '\r'<<flush;
	j++;
	for(usint bat = 0; bat < ringsize; bat++){
	  vin.push_back(ch);
	}
	PT pt= cc->MakePackedPlaintext(vin);
	vin.clear();
	CT ct = cc->Encrypt(keyPair.publicKey, pt);
	epat.push_back(ct);
  }	

  cout<<"Step 4 - Encrypted string search"<<endl;  

  TIC(auto t2);

  vecCT eresult = encrypted_search(cc, keyPair.publicKey, epat, etxt, p);
  auto encrypted_time_ms = TOC_MS(t2);
  cout<< "Encrypted execution time "<<encrypted_time_ms<<" mSec."<<endl;  

  //decrypt the result and compute location of potential matches
  vecPT vecResult(0);
  for (auto e_itr:eresult){
	PT ptresult;  
	cc->Decrypt(keyPair.secretKey, e_itr, &ptresult);
	ptresult->SetLength(pt_len);
	vecResult.push_back(ptresult);
  }

  vecInt foundloc(0);
  for (usint i = 0; i < vecResult.size(); i++) {
    auto unpackedVal = vecResult[i]->GetPackedValue();
    for (usint j = 0; j< ringsize; j++) {
      if (unpackedVal[j] == 0) {
      auto loc = i + offset[j];
      foundloc.push_back(loc);
      }
    }
  }

  sort(foundloc.begin(), foundloc.end());
  cout<<"total occurences "<<foundloc.size()<<endl;

  if (presult.size() != foundloc.size()){
	cout<<"encrypted and plaintext results do not match"<<endl; 
	
	auto smaller = min(presult.size(), foundloc.size());
	
	for (usint i = 0; i < smaller; i++) {
	  if (presult[i] != foundloc[i]) {
		cout <<"mismatch at location "<<i<<endl;
	  }
	}
	if (presult.size()<foundloc.size()) {
	  for (auto i = smaller; i< foundloc.size(); i++) {
		cout <<"encrypted extra finds "<<i<< foundloc[i]<<endl;
	  }
	} else {
	  for (auto i = smaller; i< presult.size(); i++) {
		cout <<"plaintext extra finds "<<i<<" "<< presult[i]<<endl;
	  }
	}
  } else {
	cout<<"encrypted and plaintext results match"<<endl;
  }
  return 0;
}
