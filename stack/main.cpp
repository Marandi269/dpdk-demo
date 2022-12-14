#include <iostream>
using namespace std;

#include "blocking_queue.hpp"
#include "dpdk.h"

int main(int argc, char *argv[]) {
  Dpdk dpdk(argc, argv);
  dpdk.run();
  return 0;
}