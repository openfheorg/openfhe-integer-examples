
# OpenFHE integer examples

Sample programs for Encrypted Integer Processing

# Encrypted substring search

Based on the [Rabin-Karp algorithm](https://en.wikipedia.org/wiki/Rabin–Karp_algorithm)

Source code adapted from [C++ source code published here](https://www.sanfoundry.com/cpp-program-implement-rabin-karp-method-for-string-matching/)

> src/strsearch_enc_1.cpp encrypted string search no SIMD batching

> src/strsearch_enc_2.cpp encrypted string search with SIMD batching

# Building The System

1) Install the OpenFHE library on your machine by following the [official documentation](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html). Do note that the following example has not been tested on windows or macOS.

2) Clone this repo to your local system

3) Build this code

```
mkdr build
cd build 
cmake ..
make 
```

which will generate examples in the `build/bin` directory. All input files, and resulting assembler outputs will be in various subdirectories under `examples`.
		
# Running the Examples

From the root directory, run the two string search examples with 

> `bin/strsearch_enc_1`

> `bin/strsearch_enc_2`
