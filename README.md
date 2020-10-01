# PALISADE integer examples

Sample programs for Encrypted Integer Processing

# Encrypted substring search

Based on the [Rabin-Karp algorithm](https://en.wikipedia.org/wiki/Rabin–Karp_algorithm)

Source code adapted from [C++ source code published here](https://www.sanfoundry.com/cpp-program-implement-rabin-karp-method-for-string-matching/)

> src/strsearch_enc_1.cpp encrypted string search no SIMD batching

> src/strsearch_enc_2.cpp encrypted string search with SIMD batching

# Building

Building the system
===================

Build instructions for Ubuntu
---------

Please note that we have not tried installing this on windows or
macOS. If anyone does try this, please update this file with
instructions.  It's recommended to use at least Ubuntu 18.04, and gnu g++ 7 or greater.


1. Install pre-requisites (if not already installed):
`g++`, `cmake`, `make`, and `autoconf`. Sample commands using `apt-get` are listed below. It is possible that these are already installed on your system.

> `sudo apt-get install build-essential #this already includes g++`

> `sudo apt-get install autoconf`

> `sudo apt-get install make`

> `sudo apt-get install cmake`

> Note that `sudo apt-get install g++-<version>` can be used to
install a specific version of the compiler. You can use `g++
--version` to check the version of `g++` that is the current system
default.

2. Install PALISADE on your system. This code was tested with pre-release 1.10.3.

Full instructions for this are to be found in the `README.md` file in the PALISADE repo. 

Run `make install` at the end to install the system to the default
location (you can change this location, but then you will have to
change the Makefile in this repo to reflect the new location).

3. Clone this repo onto your system.

4. Create the bin directory

> `mkdir bin`

5. Build the system using make

> `make`

All the examples will be in the `bin` directory. All input files, and resulting assembler outputs will be in various subdirectories under `examples`.

Running Simple Examples
=======================

From the root directory, run the two string search examples with 

> `bin/strsearch_enc_1`

> `bin/strsearch_enc_2`


