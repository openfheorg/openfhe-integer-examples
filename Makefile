SRC = src
BIN = bin

#CXX_FLAGS = -g -I"src" -std=c++11 -O3  -march=native -Ofast -fopenmp -D_GLIBCXX_PARALLEL   #slower 4x!!!!
CXX_FLAGS = -g -I"src" -std=c++11 -O3  -march=native -Ofast -fopenmp 

#CXX_FLAGS = -g -I"src" -std=c++11 
INCLUDES = $(SRC)/debug.h

PALISADE_INCLUDES = -I/usr/local/include/palisade -I/usr/local/include/palisade/core -I/usr/local/include/palisade/pke 

PALISADE_LIBS = -fopenmp /usr/local/lib/libPALISADEcore.so.1  /usr/local/lib/libPALISADEpke.so.1 
 
.PHONY: all

all:  $(BIN)/strsearch_plain $(BIN)/strsearch_enc_1 $(BIN)/strsearch_enc_2

.PHONY: clean
clean:
	rm -f $(SRC)/*~ $(SRC)/*.o $(BIN)/strsearch_plain $(BIN)/strsearch_enc_1  $(BIN)/strsearch_enc_2


#recipie for .o from .cpp and associated .h

#generic recipie for .o from .anything
%.o:
	g++  -O2 -I"src" -std=c++11 -c $< -o $@

#source for Test Benches
$(SRC)/strsearch_plain.o: $(SRC)/strsearch_plain.cpp  $(INCLUDES)
	g++ $(CXX_FLAGS) -c $< -o $@ $(PALISADE_INCLUDES)

$(SRC)/strsearch_enc_1.o: $(SRC)/strsearch_enc_1.cpp  $(INCLUDES)
	g++ $(CXX_FLAGS) -c $< -o $@ $(PALISADE_INCLUDES)

$(SRC)/strsearch_enc_2.o: $(SRC)/strsearch_enc_2.cpp  $(INCLUDES)
	g++ $(CXX_FLAGS) -c $< -o $@ $(PALISADE_INCLUDES)

# common modules


#final  executables
$(BIN)/strsearch_plain: $(SRC)/strsearch_plain.o
	g++  $(GXX_LINK_FLAGS) $^ -o $(BIN)/strsearch_plain $(PALISADE_LIBS)

$(BIN)/strsearch_enc_1: $(SRC)/strsearch_enc_1.o
	g++  $(GXX_LINK_FLAGS) $^ -o $(BIN)/strsearch_enc_1 $(PALISADE_LIBS)

$(BIN)/strsearch_enc_2: $(SRC)/strsearch_enc_2.o
	g++  $(GXX_LINK_FLAGS) $^ -o $(BIN)/strsearch_enc_2 $(PALISADE_LIBS)

