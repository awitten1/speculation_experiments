CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++11

.PHONY: all clean

all: spectre_v1_bounds_bypass

spectre_v1_bounds_bypass: spectre_v1_bounds_bypass.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f spectre_v1_bounds_bypass
