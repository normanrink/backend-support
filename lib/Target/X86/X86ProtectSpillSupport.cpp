//===-- X86FixupLEAs.cpp - use or replace LEA instructions -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the pass that finds instructions that can be
// re-written as LEA instructions in order to reduce pipeline delays.
//
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86InstrBuilder.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/LiveVariables.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetInstrInfo.h"
using namespace llvm;

#define DEBUG_TYPE "protect-spill"

namespace {
class ProtectSpillSupportPass : public MachineFunctionPass {
  static char ID;

  const char *getPassName() const override { return "X86 Support for protection of register spills"; }

  typedef struct {
    MachineInstr *MI;
    unsigned NativeOpcode;
    bool isFrameSetup;
    bool isEFLAGSlive;
    bool isRAXlive;  
  } CJEItem;

public:
  ProtectSpillSupportPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &Func) override;

  bool isRAXLiveAtMI(MachineInstr *MI) const;
};

char ProtectSpillSupportPass::ID = 0;
}

bool ProtectSpillSupportPass::isRAXLiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getTarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RAX, MI, true) ||
      TII->isRegLiveAtMI(X86::EAX, MI, true) ||
      TII->isRegLiveAtMI(X86::AX, MI, true) ||
      TII->isRegLiveAtMI(X86::AH, MI, true))
      // The 'AL' subregister does not matter for the purposes of the
      // 'ProtectSpillSupportPass' since the instructions for saving and
      // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;
    
  return false;
}

static MachineBasicBlock::iterator insertDoubleXchange(MachineBasicBlock::iterator I) {
  MachineBasicBlock *MBB = I->getParent();
  MachineFunction *MF = MBB->getParent();

  const TargetInstrInfo *TII = MF->getTarget().getInstrInfo();
  const X86Subtarget &STI = MF->getTarget().getSubtarget<X86Subtarget>();

  unsigned RBX = STI.is64Bit() ? X86::RBX : X86::EBX;
  unsigned XchgOpc = STI.is64Bit() ? X86::XCHG64ar : X86::XCHG32ar;

  const DebugLoc &DL = I->getDebugLoc();

  // Save 'RAX' before 'LAHF'/'SAHF' instruction:
  MachineBasicBlock::iterator result =
    BuildMI(*MBB, I, DL, TII->get(XchgOpc)).addReg(RBX);
  // Restore 'RAX' and save 'EFLAGS' in 'RBX' register after
  // 'LAHF'/'SAHF' instruction:
  BuildMI(*MBB, std::next(I), DL, TII->get(XchgOpc)).addReg(RBX);
  return result;
}

static bool isCJEOpcode(unsigned Opcode,
                        unsigned &NativeOpcode, bool &isFrameSetup) {
  bool result = false;
  NativeOpcode = ~0U;
  isFrameSetup = false;

  switch (Opcode) {
  case X86::FS_CJE64rm:
    isFrameSetup = true;
  case X86::CJE64rm:
    NativeOpcode = X86::CMP64rm;
    result = true;
    break;

  case X86::FS_CJE32rm:
    isFrameSetup = true;
  case X86::CJE32rm:
    NativeOpcode = X86::CMP32rm;
    result = true;
    break;

  case X86::FS_CJE16rm:
    isFrameSetup = true;
  case X86::CJE16rm:
    NativeOpcode = X86::CMP16rm;
    result = true;
    break;

  case X86::FS_CJE8rm:
    isFrameSetup = true;
  case X86::CJE8rm:
    NativeOpcode = X86::CMP8rm;
    result = true;
    break;

  case X86::CJEf64rm:
    NativeOpcode = X86::FCOM64m;
    break;
  case X86::CJEf32rm:
    NativeOpcode = X86::FCOM32m;
    result = true;
    break;

  default:
    break;
  }

  return result;
}

static void transformCJE(MachineBasicBlock::iterator MI,
                         unsigned NativeOpc, bool isFrameSetup,
                         bool isEFLAGSlive, bool isRAXlive) {
  const DebugLoc &DL = MI->getDebugLoc();
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getTarget().getInstrInfo());

  MachineBasicBlock::iterator JumpI = MI;
  if (!isFrameSetup && isEFLAGSlive) {
    MachineBasicBlock::iterator LAHF =
      BuildMI(*MBB, MI, DL, TII->get(X86::LAHF));
    MachineBasicBlock::iterator SAHF =
      BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SAHF));

    JumpI = SAHF;
    if (isRAXlive) {
      insertDoubleXchange(LAHF);
      JumpI = insertDoubleXchange(SAHF);
    }
  }

  MachineInstr *CmpI = BuildMI(*MBB, MI, DL, TII->get(NativeOpc));
  // Transfer all operands of the CJE instruction: (Note that operands
  // were added to CJE using the 'addFrameReference' function. Therefore,
  // the exact number and types of operands are not known.)
  unsigned StartIndex = isFrameSetup ? 0 : 1;
  for (unsigned i = StartIndex; i < MI->getNumOperands(); i++) {
    CmpI->addOperand(MI->getOperand(i));
  }

  MachineInstr *JumpMI = BuildMI(*MBB, JumpI, DL, TII->get(X86::JNE_1))
                          .addMBB(MF->getExitBlock());
  // The EFLAGS are not needed in subsequent instructions.
  // Hence, kill EFLAGS:
  JumpMI->getOperand(1).setIsKill(true);
  // Set the 'ExitJump' flag so that the jump is not mistaken as a
  // "conventional" terminator: (Not mistaking it for a terminator
  // is important for the isnertion of function epilogs.)
  JumpMI->setFlag(MachineInstr::ExitJump);
  // Add the basic block 'MBB' to the predecessors of the current
  // machine function's 'ExitBlock':
  MF->getExitBlock()->addPredecessor(MBB);

  MI->eraseFromParent();

}
bool ProtectSpillSupportPass::runOnMachineFunction(MachineFunction &Func) {
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(Func.getTarget().getInstrInfo());
  
  bool modified = false;
  SmallVector<CJEItem, 8> worklist;

  for (auto MBBI = Func.begin(), MBBE = Func.end(); MBBI != MBBE; ++MBBI) {
    for (auto MI = MBBI->begin(), ME = MBBI->end(); MI != ME; ++MI) {
      CJEItem item;
      if (isCJEOpcode(MI->getOpcode(), item.NativeOpcode, item.isFrameSetup)) {
          item.MI = MI;
          item.isEFLAGSlive = TII->isRegLiveAtMI(X86::EFLAGS, MI);
          item.isRAXlive = isRAXLiveAtMI(MI);
          // We put 'CJE'instructions on a work list. Since transforming 'CJE'
          // instructions may introduce additional uses and definitions of 'RAX'
          // (when 'EFLAGS' needs to be saved and restored). There is a change
          // that these additional definitions and uses may confuse our
          // procedure for determining live-ness. Therefore, we determine
          // live-ness of 'EFFLAGS' and 'RAX' now, and also put this 
          // information on the work list.
          worklist.push_back(item);
      }
    }
  }

  modified = !worklist.empty();

  while (!worklist.empty()) {
    CJEItem item = worklist.pop_back_val();
    transformCJE(item.MI, item.NativeOpcode, item.isFrameSetup,
                 item.isEFLAGSlive, item.isRAXlive);
  }

  return modified;
}

FunctionPass *llvm::createX86ProtectSpillSupport() { return new ProtectSpillSupportPass; }

