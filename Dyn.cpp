#include "Dyn.h" 

void Dyn::interleave(){
asm("movl $0x0, -0x18(%rbp)"); 
} 
