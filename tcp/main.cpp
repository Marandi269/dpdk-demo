
#include <iostream>
using namespace std;

#include "dpdk.h"


struct Date {
   unsigned short nWeekDay  : 3;    // 0..7   (3 bits)
   unsigned short nMonthDay : 6;    // 0..31  (6 bits)
   unsigned short nMonth    : 5;    // 0..12  (5 bits)
   unsigned short nYear     : 8;    // 0..100 (8 bits)
};


int main(int argc, char *argv[]){
    cout<< "sizeof(tf): "<< sizeof(Date) <<endl;     
    return 0;
}
