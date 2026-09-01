#include <stdint.h>

int foo(int x);
int bar(uint64_t* x);
int baz(int a);

int foo(int x) {
  int y = (x * 2) + 1;
  return y - baz(y);
}

int bar(uint64_t* x) {
  if (x != 0x0) {
    uint64_t y = *x;
    uint64_t z = 0xaaaaaaaaaaaaaaaa;
    uint64_t a = y ^ z;
    return (int) a;
  }

  return 0;
}

int baz(int a) {
  void* x = (void*) 0x7fffffffdeadbeef;
  char y = ((char*)x)[a];
  return y;
}

