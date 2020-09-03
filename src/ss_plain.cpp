/*
 * C++ program implements the Rabin-Karp method for string matching.
 * initial version of this code comes from 
 * https://www.sanfoundry.com/cpp-program-implement-rabin-karp-method-for-string-matching
 * modified by D. Cousins Dualitytech.com

 */
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "debug.h"
using namespace std;
     
// d is the number of characters in input alphabet
const int d = 256;
     
/*  pat  -> pattern
	txt  -> text
	p    -> A prime number
*/
     
void get_input_from_term(vector<char>& a) {
  string cstr;
  cin.ignore(numeric_limits<streamsize>::max(),'\n'); //flushes buffer
  std::getline(std::cin, cstr);
  for(auto c: cstr) {
	a.push_back(c);
  }
  cout <<"Pattern is "<<a.size()<<" characters"<<endl;  
  return;
}
     
void get_input_from_file(vector<char>& a, string fname) {
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
     
     
void search(vector<char> &pat, vector<char> &txt, int p) {
  DEBUG_FLAG(true);
  int M = pat.size();
  DEBUGEXP(M);
  int N = txt.size();
  DEBUGEXP(N);
  int i, j;
  int ph = 0;  // hash value for pattern
  int th = 0; // hash value for txt
  int h = 1;

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
     
int main()
{
  vector<char> txt;
  vector<char> pat;
  string infilename;

  cout<<"Enter file for Text:";
  cin >> infilename;
  get_input_from_file(txt, infilename);

  cout<<"Enter Pattern to Search:";
  get_input_from_term(pat);

  int p = 65537; //prime modulus

  
  
 search(pat, txt, p);

  return 0;
}
