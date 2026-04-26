CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++11
SRCS := spectre_v2_branch_poison.cpp run_sequence.cpp

.PHONY: all clean

all: spectre_v2_branch_poison

spectre_v2_branch_poison: $(SRCS) run_sequence.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS)

clean:
	rm -f spectre_v2_branch_poison
