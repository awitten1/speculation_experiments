#include <algorithm>
#include <random>

extern const int kStride = 32 / sizeof(int);
static_assert(sizeof(int) == 4);

void init_random_array(int* arr, int array_size) {
  for (int i = 0; i < array_size; ++i) arr[i] = i;

  std::random_device rd;
  std::mt19937 gen(rd());
  std::shuffle(arr, arr + array_size, gen);
}

void init_strided_array(int* arr, int array_sz) {
  for (int i = 0; i < array_sz; i += kStride) {
    arr[i] = kStride;
  }
}

void init_sa_rv_array(int* arr, int array_size) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(kStride, array_size-1);
  for (int i = 0; i < array_size; ++i) {
    arr[i] = dist(gen);
  }
}
