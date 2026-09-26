// Times each phase of the address resolution, to check it fits inside the
// window between process start and the engine parsing common/diplomatic_actions.
//
// usage: time_resolve.exe <stellaris.exe>

#include <chrono>
#include <cstdio>

#include "../src/anchor.h"
#include "../src/resolver.h"

using Clock = std::chrono::steady_clock;
static double Ms(Clock::time_point a, Clock::time_point b) {
  return std::chrono::duration<double, std::milli>(b - a).count();
}

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  auto t0 = Clock::now();
  anchor::Image image;
  if (!image.InitFromFile(argv[1])) {
    fprintf(stderr, "cannot load %s\n", argv[1]);
    return 2;
  }
  auto t1 = Clock::now();
  diplo::Resolved r;
  diplo::ResolveAll(image, &r);
  auto t2 = Clock::now();

  printf("load+parse .pdata : %8.1f ms (%zu functions)\n", Ms(t0, t1),
         image.Functions().size());
  printf("ResolveAll        : %8.1f ms  ok=%d (%s)\n", Ms(t1, t2), r.ok ? 1 : 0,
         r.failure);
  printf("total             : %8.1f ms\n", Ms(t0, t2));
  return 0;
}
