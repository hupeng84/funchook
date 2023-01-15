/**
 * Copyright 2023 hupeng.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <memory>

#include "funchook.h"

int hello(int a, int b) {
  return a + b;
}

int main(int, char**) {
  auto beforeSum = hello(5, 8);
  std::cout << "before hook: sum = " << beforeSum << std::endl;

  auto funcHook = std::make_unique<FuncHook<int, int, int>>();
  funcHook->Hook((void*)&hello, [](int a, int b) -> int { return a - b; });

  auto afterSum = hello(5, 8);
  std::cout << "after hook: sum = " << afterSum << std::endl;
  return 0;
}
