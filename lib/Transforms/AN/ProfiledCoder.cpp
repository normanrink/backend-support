
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Value.h"

#include "ProfiledCoder.h"
#include "UsesVault.h"


#define DEBUG_TYPE "an-encoder"

ProfiledCoder::ProfiledCoder (Module *m, unsigned a, bool int32)
: M(m), Int32(int32) {
	LLVMContext &ctx = M->getContext();

	int64Ty = Type::getInt64Ty(ctx);
	int32Ty = Type::getInt32Ty(ctx);
	voidTy  = Type::getVoidTy(ctx);
  pointerTy = Type::getInt64PtrTy(ctx);

	A = ConstantInt::getSigned(int64Ty, a);

  {
	  SmallVector<Type*, 2> oneArg64, twoArgs64;
	  oneArg64.push_back(int64Ty);

	  FunctionType *oneArg64Int64Ty = FunctionType::get(int64Ty, oneArg64, false);
	  FunctionType *oneArg64VoidTy  = FunctionType::get(voidTy,  oneArg64, false);

  	Encode_64 = M->getFunction("an_encode_64"); //, oneArg64Int64Ty);
	  Decode_64 = M->getFunction("an_decode_64"); //, oneArg64Int64Ty);
  }

  /*
  {
	  SmallVector<Type*, 2> oneArg32, twoArgs32;
	  oneArg32.push_back(int32Ty);

	  FunctionType *oneArg32Int32Ty = FunctionType::get(int32Ty, oneArg32, false);
	  FunctionType *oneArg32VoidTy  = FunctionType::get(voidTy,  oneArg32, false);

  	Encode_32 = M->getFunction("an_encode_32", oneArg32Int32Ty);
	  Decode_32 = M->getFunction("an_decode_32", oneArg32Int32Ty);
	}
  */

  /*
	IncLoads = M->getOrInsertFunction("incLoads", 
                                    FunctionType::get(voidTy, int64Ty, false));
  */
  Builder = new IRBuilder<>(ctx);
}

ProfiledCoder::~ProfiledCoder() {
  delete Builder;
}

IntegerType *ProfiledCoder::getInt64Type() const {
  return this->int64Ty;
}

IntegerType *ProfiledCoder::getInt32Type() const {
  return this->int32Ty;
}

IntegerType *ProfiledCoder::getIntType() const {
  if (Int32)
    return getInt32Type();
  else
    return getInt64Type();
}

Constant *ProfiledCoder::getEncode() const {
  if (Int32)
    return Encode_32;
  else
    return Encode_64;
}

Constant *ProfiledCoder::getDecode() const {
  if (Int32)
    return Decode_32;
  else
    return Decode_64;
}

Type *ProfiledCoder::getVoidType() const {
  return this->voidTy;
}

int64_t ProfiledCoder::getA() const {
  return A->getSExtValue();
}

Module* ProfiledCoder::getModule() const {
  return M;
}

Value *ProfiledCoder::createEncode(Value *V, Instruction *I) {
  Type *type = V->getType();
  if (!type->isPointerTy() && !type->isIntegerTy())
    return V;

	Builder->SetInsertPoint(I);
  if (type->isPointerTy())
    V = Builder->CreatePtrToInt(V, getIntType());
  else if (type->isIntegerTy() && type != getIntType())
    V = Builder->CreateCast(Instruction::SExt, V, getIntType());
  
	V = Builder->CreateCall(getEncode(), V);

	Builder->SetInsertPoint(I);
  if (type->isPointerTy())
    V = Builder->CreateIntToPtr(V, type);
  else if (type->isIntegerTy() && type != getIntType())
    V = Builder->CreateCast(Instruction::Trunc, V, type);

  assert(V->getType() == type);
  return V;
}

Value *ProfiledCoder::createDecode(Value *V, Instruction *I) {
  Type *type = V->getType();
  if (!type->isPointerTy() && !type->isIntegerTy())
    return V;

	Builder->SetInsertPoint(I);
  if (type->isPointerTy())
    V = Builder->CreatePtrToInt(V, getIntType());
  else if (type->isIntegerTy() && type != getIntType())
    V = Builder->CreateCast(Instruction::SExt, V, getIntType());
  
  V = Builder->CreateCall(getDecode(), V);

	Builder->SetInsertPoint(I);
  if (type->isPointerTy())
    V = Builder->CreateIntToPtr(V, type);
  else if (type->isIntegerTy() && type != getIntType())
    V = Builder->CreateCast(Instruction::Trunc, V, type);

  assert(V->getType() == type);
  return V;
}

bool ProfiledCoder::isInt64Type(Value *v) const {
	return v->getType() == getInt64Type();
}

bool ProfiledCoder::isPointerType(Value *v) const {
	return v->getType()->isPointerTy();
}

bool ProfiledCoder::handleMemory(Instruction *I) {
	unsigned opcode = I->getOpcode();

	switch(opcode) {
	case Instruction::Load: return handleLoad(I);
	case Instruction::Store: return handleStore(I);
	default: assert(0);
	}

	return false;
}

static bool isFunctionOfInterest(const Function &MF) {
  if (MF.getName().equals("___enc_sum") ||
      MF.getName().equals("___enc_bubblesort") ||
      MF.getName().equals("crc32file") ||
      MF.getName().equals("ip") || MF.getName().equals("ip_inverse") ||
      MF.getName().equals("fk") || MF.getName().equals("f") ||
      MF.getName().equals("___enc_dijkstra") ||
//      MF.getName().equals("lex") ||
      MF.getName().equals("evalNode") ||
//      MF.getName().equals("parse") ||
      MF.getName().equals("fib") ||
      MF.getName().equals("___enc_multiply") ||
      MF.getName().equals("___enc_copy") ||
      MF.getName().equals("quicksort") ||
      MF.getName().equals("rec_copy") ||
      MF.getName().equals("___enc_select"))
    return true;

  return false;
}

bool ProfiledCoder::handleLoad(Instruction *I) {
  LoadInst *LI = dyn_cast<LoadInst>(I);
  assert(LI);

  UsesVault UV(LI->uses());
  BasicBlock::iterator BBI = I;
  Value *Result = createDecode(LI, std::next(BBI));
  if (Result != LI)
    UV.replaceWith(Result);

  /*
  if (CntLoads && isFunctionOfInterest(*I->getParent()->getParent())) {
	  Builder->SetInsertPoint(I);
    Value *addr = Builder->CreateCast(Instruction::PtrToInt,
                                      LI->getPointerOperand(),
                                      getInt64Type());
    Builder->CreateCall(IncLoads, addr);
  }
  */

  return true;
}

bool ProfiledCoder::handleStore(Instruction *I) {
  StoreInst *SI = dyn_cast<StoreInst>(I);
  assert(SI);

  Value *V = SI->getValueOperand();
  V = createEncode(V, I);

  Builder->SetInsertPoint(I);
  StoreInst *NewSI = Builder->CreateAlignedStore(V, SI->getPointerOperand(),
                                                 SI->getAlignment(), SI->isVolatile());
  /*
  if (CntLoads) {
	  Builder->SetInsertPoint(I);
    Value *addr = Builder->CreateCast(Instruction::PtrToInt,
                                      SI->getPointerOperand(),
                                      getInt64Type());
    Builder->CreateCall(IncLoads, addr);
  }
  */

  I->replaceAllUsesWith(NewSI);
  I->eraseFromParent();
  return true;
}

