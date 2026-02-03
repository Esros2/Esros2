#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ebpfMod.skel.h"

int main(int argc, const char * const * argv)
{
      struct iter * skel = ebpfMod__open();
      ebpfMod__load(skel);
      ebpfMod__attach(skel);

      while(1){
   
      }
      return 0;
}
