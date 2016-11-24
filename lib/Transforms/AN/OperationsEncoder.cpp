
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"

#include "ProfiledCoder.h"


#define DEBUG_TYPE "an-encoder"

namespace llvm {

struct OperationsEncoder : public BasicBlockPass {
  OperationsEncoder(unsigned a)
  : BasicBlockPass(ID), A(a) {}

  bool runOnBasicBlock(BasicBlock &BB) override;

  static char ID;

private:
  const unsigned A;

  void insertHelpers(Module &M) const;
};

BasicBlockPass *createOperationsEncoder(unsigned a) {
  return new OperationsEncoder(a);
}

char OperationsEncoder::ID = 0;

bool OperationsEncoder::runOnBasicBlock(BasicBlock &BB) {
  bool modified = false;
  LLVMContext &ctx = BB.getContext();
  Module *M = BB.getParent()->getParent();

  insertHelpers(*M);
  ProfiledCoder PC = ProfiledCoder(M, A);

  auto I = BB.begin(), E = BB.end();
  while( I != E) {
    auto N = std::next(I);
    unsigned Op = I->getOpcode();
    switch (Op) {
    default: {
    	break;
    }
    case Instruction::Load:
    case Instruction::Store: {
    	modified |= PC.handleMemory(I);
    	break;
    }
    }
    I = N;
  }

  return modified;
}

void OperationsEncoder::insertHelpers(Module &M) const {
	LLVMContext &ctx = M.getContext();
  IRBuilder<> Builder(ctx);

	Type* int128Ty = Type::getIntNTy(ctx, 128);

	Type* int64Ty = Type::getInt64Ty(ctx);
	SmallVector<Type*, 1> oneArg64;
	oneArg64.push_back(int64Ty);
	FunctionType *oneArg64Int64Ty = FunctionType::get(int64Ty, oneArg64, false);

  Constant *A = ConstantInt::getSigned(int128Ty, this->A);

  if (!M.getFunction("an_encode_64")) {
    Function *encoder = Function::Create(oneArg64Int64Ty, GlobalValue::InternalLinkage,
                                         "an_encode_64", &M);

    BasicBlock *entry = BasicBlock::Create(ctx, "entry", encoder);

    Builder.SetInsertPoint(entry);
    Value *ext = Builder.CreateZExt(encoder->arg_begin(), int128Ty);
    Value *enc = Builder.CreateMul(ext, A);

    Value *lower = Builder.CreateShl(enc, ConstantInt::get(int128Ty, 64));
    lower = Builder.CreateLShr(lower, ConstantInt::get(int128Ty, 64));
    lower = Builder.CreateTrunc(lower, int64Ty);
    lower = Builder.CreateAnd(lower, ConstantInt::get(int64Ty, ~0xFFFF));

    Value *upper = Builder.CreateLShr(enc, ConstantInt::get(int128Ty, 64));
    upper = Builder.CreateTrunc(upper, int64Ty);
    
    Value *result = Builder.CreateOr(upper, lower);
    Builder.CreateRet(result);
  }

  if (!M.getFunction("an_decode_64")) {
    Function *decoder = Function::Create(oneArg64Int64Ty, GlobalValue::InternalLinkage,
                                         "an_decode_64", &M);

    //BasicBlock *ret   = BasicBlock::Create(ctx, "ret",   decoder);
    //BasicBlock *exit  = BasicBlock::Create(ctx, "exit",  decoder, ret);
    //BasicBlock *entry = BasicBlock::Create(ctx, "entry", decoder, exit);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", decoder);

    Value *dec;
    {
      //Value *enc, *eq;
      Builder.SetInsertPoint(entry);
      //dec = Builder.CreateSDiv(decoder->arg_begin(), A);
      //enc = Builder.CreateMul(dec, A);
      //eq  = Builder.CreateICmpEQ(decoder->arg_begin(), enc);
      Value *upper = Builder.CreateAnd(decoder->arg_begin(),
                                       ConstantInt::get(int64Ty, 0xFFFF));
      upper = Builder.CreateZExt(upper, int128Ty);

      Value *lower = Builder.CreateAnd(decoder->arg_begin(),
                                       ConstantInt::get(int64Ty, ~0xFFFF));
      lower = Builder.CreateZExt(lower, int128Ty);

      Value *enc = Builder.CreateShl(upper, ConstantInt::get(int128Ty, 64));
      enc = Builder.CreateOr(enc, lower);

      dec = Builder.CreateUDiv(enc, A);
      Value *re_enc = Builder.CreateMul(dec, A);
      Value *eq = Builder.CreateICmpEQ(enc, re_enc);

      //Builder.CreateCondBr(eq, ret, exit);
      dec = Builder.CreateTrunc(dec, int64Ty);
      Builder.CreateRet(dec);
    }
    /*
    {
      Builder.SetInsertPoint(exit);
    
	    Type *int32Ty = Type::getInt32Ty(ctx);
	    Type *voidTy  = Type::getVoidTy(ctx);
	    SmallVector<Type*, 1> oneArg32;
      oneArg32.push_back(int32Ty);
	    FunctionType *oneArg32VoidTy = FunctionType::get(voidTy,  oneArg32, false);

      Builder.CreateCall(M.getOrInsertFunction("exit", oneArg32VoidTy),
                         ConstantInt::getSigned(int32Ty, 2));
      Builder.CreateUnreachable();
    }

    {
      Builder.SetInsertPoint(ret);
      dec = Builder.CreateTrunc(dec, int64Ty);
      Builder.CreateRet(dec);
    }
    */
  }
}

}

