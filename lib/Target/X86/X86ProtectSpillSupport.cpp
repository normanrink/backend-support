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
//#include "llvm/CodeGen/MachineFrameInfo.h"
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

  typedef std::pair<MachineInstr*, MachineInstr*> LSPair;

public:
  ProtectSpillSupportPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &Func) override;
};

char ProtectSpillSupportPass::ID = 0;
}

static bool isRAXLiveAtMI(MachineInstr *MI) {
  if (X86InstrInfo::isRegLiveAtMI(X86::RAX, MI) ||
      X86InstrInfo::isRegLiveAtMI(X86::EAX, MI) ||
      X86InstrInfo::isRegLiveAtMI(X86::AX, MI) ||
      X86InstrInfo::isRegLiveAtMI(X86::AH, MI) ||
      X86InstrInfo::isRegLiveAtMI(X86::AL, MI))
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

bool ProtectSpillSupportPass::runOnMachineFunction(MachineFunction &Func) {
  bool modified = false;
  
  for (auto MBBI = Func.begin(), MBBE = Func.end(); MBBI != MBBE; ++MBBI) {
    auto MI = MBBI->begin(), ME = MBBI->end(); 
    while (MI != ME) {
      auto NI = std::next(MI);
      
      unsigned OpcCmp = ~0U;
      switch (MI->getOpcode()) {
      case X86::CJE64rm:
          OpcCmp = X86::CMP64rm;
          break;
      case X86::CJE32rm:
          OpcCmp = X86::CMP32rm;
          break;
      case X86::CJE16rm:
          OpcCmp = X86::CMP16rm;
          break;
      case X86::CJE8rm:
          OpcCmp = X86::CMP8rm;
          break;
      default:
          break;
      }

      if (OpcCmp != ~0U) {
        const DebugLoc &DL = MI->getDebugLoc();
          MachineBasicBlock *MBB = MI->getParent();
        MachineFunction *MF = MBB->getParent();
        const TargetInstrInfo *TII = MF->getTarget().getInstrInfo();

        bool liveFlags = X86InstrInfo::isRegLiveAtMI(X86::EFLAGS, MI);
        bool liveRAX = isRAXLiveAtMI(MI);

        MachineBasicBlock::iterator JumpI = MI;
        if (liveFlags) {
          MachineBasicBlock::iterator LAHF =
            BuildMI(*MBB, MI, DL, TII->get(X86::LAHF));
          MachineBasicBlock::iterator SAHF = 
            BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SAHF));

          JumpI = SAHF;
          if (liveRAX) {
            insertDoubleXchange(LAHF);
            JumpI = insertDoubleXchange(SAHF);
          }
        }

        MachineInstr *CmpI = BuildMI(*MBB, MI, DL, TII->get(OpcCmp));
        // Transfer all operands of the CJE instruction: (Note that operands
        // were added to CJE using the 'addFrameReference' function. Therefore,
        // the exact number and types of operands are not known.)
        for (unsigned i = 0; i < MI->getNumOperands(); i++) {
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
        modified = true;
      }

      MI =  NI;
    }
  }

  return modified;
}

FunctionPass *llvm::createX86ProtectSpillSupport() { return new ProtectSpillSupportPass; }

