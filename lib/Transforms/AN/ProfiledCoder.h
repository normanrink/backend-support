#ifndef __PROFILED_CODER_H__
#define __PROFILED_CODER_H__

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Metadata.h"

#include <set>


using namespace llvm;


class CallHandler;
class ExpandGetElementPtr;
class InterfaceHandler;

class ProfiledCoder {
public:
	ProfiledCoder(Module *m, unsigned a=1, bool int32 = false);
	~ProfiledCoder();

public:
	Value *createEncode(Value *V, Instruction *I);
	Value *createDecode(Value *V, Instruction *I);

public:
	IntegerType *getInt64Type() const;
	IntegerType *getInt32Type() const;
	IntegerType *getIntType() const;
	Type *getVoidType() const;
	int64_t getA() const;
	int64_t getGcd() const;
	Module* getModule() const;

public:
	bool isInt64Type(Value *v) const;
	bool isPointerType(Value *v) const;

private:
	bool handleLoad(Instruction *I);
	bool handleStore(Instruction *I);
	
public:
  bool handleMemory(Instruction *I);

private:
	Module *M;
  //bool CntLoads;
  bool Int32;

	ConstantInt *A, *MultInv;
  int64_t gcd;

	IntegerType *int64Ty, *int32Ty;
	Type *voidTy;
  PointerType *pointerTy;
	Constant *Blocker, *Multiplier, *MultUp;
	InlineAsm *BlockerAsm, *MultiplierAsm, *MultUpAsm;
	Constant *Encode_64, *Decode_64, *Check, *Assert, *ExitOnFalse;
	Constant *Encode_32, *Decode_32;
	Constant *Exit, *Accumulate;

  Constant *getEncode() const;
  Constant *getDecode() const;

  Constant *IncLoads;

	IRBuilder<> *Builder;
};

#endif /* __PROFILED_CODER_H__ */
