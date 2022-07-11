/* PALISADE C++ program implements the Rabin-Karp method for string
 * matching using encrypted computation and no SIMD batching
 * plaintext version of this code comes from
 * https://www.sanfoundry.com/cpp-program-implement-rabin-karp-method-for-string-matching
 * author David Bruce Cousins@dualitytech.com
 */


#include <cstring>
#include <iostream>
#include <vector>
#include "openfhe.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"
#include "debug_utils.h"
using namespace std;

//data types we will need
using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ; //ciphertext
using PT = lbcrypto::Plaintext ; //plaintext
using vecCT = vector<CT>; //vector of ciphertexts
using vecPT = vector<PT>; //vector of plaintexts
using vecInt = vector<int64_t>; // vector of ints
using vecChar = vector<char>; // vector of characters

// d is the number of characters in input alphabet
const int d = 256;

//  pat  -> pattern
//	txt  -> text
//	p    -> A prime number

// function to get string input from terminal and return as vector of char
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

// function to read text from a file and return as vector of char
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

// plaintext string search of pat within txt, with modulus of ps
vecInt search(vecChar &pat, vecChar &txt, int ps) {
  int64_t p(ps);
  DEBUG_FLAG(false);
  size_t M = pat.size();
  DEBUGEXP(M);
  size_t N = txt.size();
  DEBUGEXP(N);
  size_t i, j;
  int64_t ph = 0;  // hash value for pattern
  int64_t th = 0; // hash value for txt
  int64_t h = 1;

  size_t nfound = 0;

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

    }
  } //end for

  cout<<"total occurances " <<nfound<<endl;
  return pres;
}

// helper function to encrypt an integer repeatedly into a packed plaintext
// and encrypt it
CT encrypt_repeated_integer(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc, lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk,  int64_t in, size_t n){

  vecInt v_in(n, in);
  PT pt= cc->MakePackedPlaintext(v_in);
  CT ct = cc->Encrypt(pk, pt);

  return ct;
}

// helper function to multiply by constant 256 using binary tree addition
CT encMultD(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc, CT in){
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

//Single value encrypted search
vecCT encrypted_search(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,  lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk, vecCT &epat, vecCT &etxt, int ps) {

  int64_t p(ps);
  DEBUG_FLAG(false);
  size_t M = epat.size();
  DEBUGEXP(M);
  size_t N = etxt.size();
  DEBUGEXP(N);
  size_t i;

  PT dummy;

  size_t nrep(1);
  DEBUG("encrypting small ct");
  CT phct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for pattern
  CT thct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for txt

  DEBUG("encrypting hct");
  // The value of h would be "pow(d, M-1)%p"
  int64_t h = 1;
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
  vecChar bigtxt;

  vecChar pat;
  string infilename;

  //Note inputs are hardwired, uncomment to add user control
  //cout<<"Enter file for Text:";
  //cin >> infilename;
  infilename = "data/annakarenina.txt";
  get_input_from_file(bigtxt, infilename);

  //cout<<"Enter text size:";
  uint32_t textSize(0);
  //cin>> textSize;
  textSize = 32;
  uint32_t offset(16);
  cout << "Limiting search to "<<textSize<< " characters "
	  <<"starting at offset "<<offset<<endl;

  vecChar::const_iterator first = bigtxt.begin() + offset;
  vecChar::const_iterator last = bigtxt.begin() + offset+textSize;
  vecChar txt(first, last);

  //Note inputs are hardwired, uncomment to add user control
  //cout<<"Enter Pattern to Search:";
  //get_input_from_term(pat);
  pat = {'A', 'n', 'n', 'a'};

  int p = 786433; //plaintext prime modulus
  //int p = 65537; //note this causes exception

  cout<<"p "<<p<<endl;
  TIC(auto t1);

  auto presult = search(pat, txt, p);
  auto plain_time_ms = TOC_MS(t1);
  cout<< "Plaintext execution time "<<plain_time_ms<<" mSec."<<endl;

  cout <<"setting up BFV RNS crypto system"<<endl;

  uint32_t plaintextModulus = p;
  uint32_t multDepth = 32;

  double sigma = 3.2;
  lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_128_classic;

  // TODO: check params as per https://palisade.gitlab.io/palisade-development/classlbcrypto_1_1CryptoContextFactory.html#a6b804ce1d8241d9158fc0bc11b7e6bc1
    /**
     * Old implementation:
      lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::genCryptoContextBFVrns(
          plaintextModulus, securityLevel, sigma, 0, multDepth, 0, OPTIMIZED);
     */
  lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetStandardDeviation(sigma);
    parameters.SetMultiplicativeDepth(multDepth);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc = lbcrypto::GenCryptoContext(parameters);

    // Instantiate the crypto context


  // Enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    cout<<"Step 2 - Key Generation"<<endl;

  // Initialize Public Key Containers
  // Generate a public/private key pair
  auto keyPair = cc->KeyGen();

  // Generate the relinearization key
  cc->EvalMultKeyGen(keyPair.secretKey);

  cout<<"Step 3 - Encryption"<<endl;

  cout<<"Step 3.1 - Encrypt pattern"<<endl;
  //encrypt the pattern
  vecInt vin(0);
  vecCT epat(0);
  uint32_t j(0);
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
  uint32_t nbatch = int(ceil(float(txt.size())/float(ringsize)));
  cout << "can store "<<nbatch <<" batches in the ct"<<endl;

  cout<<"Step 3.2 - Encrypt text"<<endl;
  vecCT etxt(0);
  auto pt_len(0);
  for (usint i = 0; i < txt.size(); i++) {
    cout<<i<< '\r'<<flush;

    vin.push_back(txt[i]);
    lbcrypto::Plaintext pt= cc->MakePackedPlaintext(vin);
    pt_len = pt->GetLength();
    vin.clear();
    CT ct = cc->Encrypt(keyPair.publicKey, pt);
    etxt.push_back(ct);
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

  return 0;
}
