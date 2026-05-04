#!/bin/bash

set -euo pipefail

cmake -B build -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build
