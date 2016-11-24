
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"


#define DEBUG_TYPE "an-encoder"

namespace llvm {

BasicBlockPass *createOperationsEncoder(unsigned);
ModulePass *createGlobalsEncoder(unsigned);

struct ANEncoder : public ModulePass {
  ANEncoder() : ModulePass(ID) {
    OE = createOperationsEncoder(A);
    GE = createGlobalsEncoder(A);
  }

  bool runOnModule(Module &M) override;

  static char ID;

private:
  //const unsigned A = 58659;
  //const unsigned A = 7;
  const unsigned A = 1 << 16;

  BasicBlockPass *OE;
  ModulePass *GE;
};

Pass *createANEncoder() {
  return new ANEncoder();
}

char ANEncoder::ID = 0;

bool ANEncoder::runOnModule(Module &M) {
  bool modified = false;

  modified |= GE->runOnModule(M);

  for (auto F = M.begin(); F != M.end(); F++) {
    for (auto BB = F->begin(); BB != F->end(); BB++) {
      modified |= OE->runOnBasicBlock(*BB);
    }
  }

  return modified;
}

}

