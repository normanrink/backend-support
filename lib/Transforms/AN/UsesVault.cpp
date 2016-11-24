
#include "UsesVault.h"

using namespace llvm;

void UsesVault::replaceWith(Value *V) {
  use_iterator I = Uses.begin(), E = Uses.end();
  while (I != E) {
    use_iterator N = std::next(I);
    I->set(V);
    I = N;
  }
}
