#include <vector>
#include <iostream>
#include <random>
#include <stddef.h>

struct SomeData {
  double adder = 0.0;
  double subber = 0.0;
};

constexpr size_t data_size = 700'000'000;

int main(int argc, char** argv) {
  std::random_device rd;
  std::mt19937 e2(rd());
  std::uniform_real_distribution<> dist(1.0, 100.0);
  std::vector<SomeData> data;
  data.reserve(data_size);

  for(size_t i = 0; i < data_size; i++) {
    data.push_back(SomeData{dist(e2), dist(e2)});
  }
  
  std::cout << "data generated" << std::endl;

  double result = 0.0;
  for(size_t i = 0; i < data_size; i++) {
    result += data[i].adder;
    result -= data[i].subber;
  }

  std::cout << "result was: " << result << std::endl;
}
