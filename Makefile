SRC = src
BIN = bin

#CXX_FLAGS = -g -I"src" -std=c++11 -O3  -march=native -Ofast -fopenmp -D_GLIBCXX_PARALLEL   #slower 4x!!!!
CXX_FLAGS = -g -I"src" -std=c++11 -O3  -march=native -Ofast -fopenmp 

#CXX_FLAGS = -g -I"src" -std=c++11 
INCLUDES = $(SRC)/debug.h

PALISADE_INCLUDES = -I/usr/local/include/palisade -I/usr/local/include/palisade/core -I/usr/local/include/palisade/pke

PALISADE_LIBS = -fopenmp /usr/local/lib/libPALISADEcore.so.1  /usr/local/lib/libPALISADEpke.so.1 
 
.PHONY: all

all:  $(BIN)/ss_plain

.PHONY: clean
clean:
	rm -f $(SRC)/*~ $(SRC)/*.o $(BIN)/ss_plain


#recipie for .o from .cpp and associated .h

#generic recipie for .o from .anything
%.o:
	g++  -O2 -I"src" -std=c++11 -c $< -o $@

#source for Test Benches
$(SRC)/ss_plain.o: $(SRC)/ss_plain.cpp  $(INCLUDES)
	g++ $(CXX_FLAGS) -c $< -o $@ $(PALISADE_INCLUDES)

# common modules


#final  executables
$(BIN)/ss_plain: $(SRC)/ss_plain.o
	g++  $(GXX_LINK_FLAGS) $^ -o $(BIN)/ss_plain $(PALISADE_LIBS)

