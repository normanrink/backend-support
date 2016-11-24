#ifndef __USESVAULT_H__
#define __USESVAULT_H__

#include "llvm/IR/Value.h"

using namespace llvm;

// 'UsesVault' is a wrapper struct that allows the uses of a value
// to be put "in the vault" for processing at a later time. The
// typical application of 'UsesVault' is where a value's uses U
// need to be marked for replacing with a value V that has not been
// created yet. If the creation of the new value V affects the uses
// U, then it is necessary to put U into the vault before creating V.
struct UsesVault {
  typedef Value::use_iterator use_iterator;
  UsesVault(iterator_range<use_iterator> u) : Uses(u) {}

  void replaceWith(Value *V);
private:
  iterator_range<use_iterator> Uses;
};
#endif /* __USESVAULT_H__ */
