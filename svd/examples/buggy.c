#include <stdio.h>
#include <string.h>

int f(int n){
  int a[10]; int i, sum;  // sum uninitialized
  for(i=0;i<=10;i++) sum += a[i]; // OOB + uninit use
  int *p = 0;
  return *p + (100/n); // null deref + div by zero if n==0
}

int main(int argc, char** argv){
  char dst[8];
  char *src = argv[1]; // taint source
  strcpy(dst, src);    // potential overflow
  printf("%s\n", dst);
  return f(argc-1);
}