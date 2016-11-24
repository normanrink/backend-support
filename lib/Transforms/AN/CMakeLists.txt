add_llvm_library(LLVMAN
  ANEncoder.cpp
  OperationsEncoder.cpp
  GlobalsEncoder.cpp
  ProfiledCoder.cpp
  UsesVault.cpp
  )

#add_dependencies(LLVMInstrumentation intrinsics_gen)
