#include <iostream>
#include "dpdk.h"

using namespace std;

int main(int argc, char* argv[]){
    cout<<"dpdk in cpp..."<<endl;
    Dpdk dpdk(argc, argv);
    cout<<"dpdk: "<<dpdk.portId<<endl;
    dpdk.run();
    return 0;   
}