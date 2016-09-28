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

#define DEBUG_TYPE "protect-return-ptr"

namespace {
class ProtectReturnSupportPass : public MachineFunctionPass {
  static char ID;

  const char *getPassName() const override { return "X86 Support for return instruction protection"; }

public:
  ProtectReturnSupportPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &Func) override;

  bool handleCallInst(MachineBasicBlock &MM, MachineInstr *MI);
  bool handleReturnInst(MachineBasicBlock &MM, MachineInstr *MI);
};

char ProtectReturnSupportPass::ID = 0;
}

bool ProtectReturnSupportPass::runOnMachineFunction(MachineFunction &Func) {
  if (!Func.protectReturnPtr())
    return false;

  bool modified = false;
  
  if (!Func.getName().equals("main")) {
    const TargetInstrInfo &TII = *Func.getTarget().getInstrInfo();
    const X86Subtarget &STI = Func.getTarget().getSubtarget<X86Subtarget>();

    unsigned Reg = STI.is64Bit() ? X86::R11 : X86::EDX;
    unsigned PushOpc = STI.is64Bit() ? X86::PUSH64r : X86::PUSH32r;

    MachineBasicBlock *MBB = Func.begin();
    MachineBasicBlock::iterator MI = MBB->begin();

    const DebugLoc &DL = MI->getDebugLoc();
    BuildMI(*MBB, MI, DL, TII.get(PushOpc)).addReg(Reg, RegState::Kill);
 
    modified = true;
  }

  for (MachineFunction::iterator MBB = Func.begin(); MBB != Func.end(); MBB++) {
    MachineBasicBlock::iterator MI = MBB->begin();
    while(MI != MBB->end()) {
      MachineBasicBlock::iterator NMI = std::next(MI);

      modified |= handleCallInst(*MBB, MI);
  
      if (!Func.getName().equals("main"))
        modified |= handleReturnInst(*MBB, MI);

      MI = NMI;
    }
  }

  return modified;
}

bool ProtectReturnSupportPass::handleCallInst(MachineBasicBlock &MBB, MachineInstr *MI) {
  if (!MI->isCall())
    return false;
      
  MachineFunction &MF = *MBB.getParent();
  const X86RegisterInfo *RegInfo =
      static_cast<const X86RegisterInfo *>(MF.getTarget().getRegisterInfo());
  const TargetInstrInfo &TII = *MF.getTarget().getInstrInfo();
  const DebugLoc &DL = MI->getDebugLoc();

  unsigned CallOpcSize = 0;
  if (MI->getOpcode() == X86::CALL64pcrel32) {
    CallOpcSize = 5;
  } else if (MI->getOpcode() == X86::CALL64r) {
    assert(MI->getOperand(0).isReg());
    unsigned Reg = MI->getOperand(0).getReg();

    if (Reg >= X86::R8)
      CallOpcSize = 3;
    else
      CallOpcSize = 2;

  } else if (MI->getOpcode() == X86::CALL64m) {
    bool hasGA = false;
    for (unsigned i = 0; i < MI->getNumOperands(); i++)
      hasGA |= MI->getOperand(i).isGlobal();

    if (hasGA)
      CallOpcSize = 7;
    else
      CallOpcSize = 3;

  } else  {
    DEBUG({dbgs() << "unhandled call opcode\n";
           MI->dump();
           dbgs() << "no. operands: " << MI->getNumOperands() << "\n";});
    llvm_unreachable("unhandled call opcode");
  }

  addRegOffset(BuildMI(MBB, MI, DL, TII.get(X86::LEA64r), X86::R11),
               X86::RIP, /* isKill */ false, CallOpcSize);

  return true;
}

bool ProtectReturnSupportPass::handleReturnInst(MachineBasicBlock &MBB, MachineInstr *MI) {
  if (!MI->isReturn())
    return false;
      
  MachineFunction &MF = *MBB.getParent();
  const DebugLoc &DL = MI->getDebugLoc();

  const X86RegisterInfo *RegInfo =
      static_cast<const X86RegisterInfo *>(MF.getTarget().getRegisterInfo());
  unsigned StackPtr = RegInfo->getStackRegister();
  unsigned SlotSize = RegInfo->getSlotSize();
  const TargetInstrInfo &TII = *MF.getTarget().getInstrInfo();
  const X86Subtarget &STI = MF.getTarget().getSubtarget<X86Subtarget>();

  unsigned Reg = STI.is64Bit() ? X86::R11 : X86::EDX;
  unsigned PopOpc = STI.is64Bit() ? X86::POP64r : X86::POP32r;
  const TargetRegisterClass *RC = X86::GR64RegClass.contains(Reg) ? &X86::GR64RegClass
                                                                  : &X86::GR32RegClass;
  
  if (MI->getOpcode() == X86::TAILJMPd64) {
    // For tail jumps, the duplicated return address from the stack must be put into the 'r11' register:
    BuildMI(MBB, MI, DL, TII.get(PopOpc), Reg);
    return true;
  }

  BuildMI(MBB, MI, DL, TII.get(PopOpc), Reg);
  unsigned CmpOpc = TII.getCompareRegAndStackOpcode(RC);

  addRegOffset(BuildMI(MBB, MI, DL, TII.get(CmpOpc)).addReg(Reg), 
               STI.is64Bit() ? X86::RSP : X86::ESP, /* isKill */ false, 0);
  BuildMI(MBB, MI, DL, TII.get(X86::JNE_1)).addMBB(MF.getExitBlock());
  MF.getExitBlock()->addPredecessor(&MBB);
  
  // Replace the return instruction with an increment of the stack pointer, followed by an
  // indirect jump (in order to avoid another implicit stack access by the return instruction): 
  unsigned AddOpc = STI.is64Bit() ? X86::ADD64ri8 : X86::ADD32ri8; 
  MachineInstr *mi = BuildMI(MBB, MI, DL, TII.get(AddOpc), StackPtr)
                       .addReg(StackPtr).addImm(SlotSize);
  mi->getOperand(3).setIsDead(); // The EFLAGS implicit def is dead.

  unsigned JmpOpc = STI.is64Bit() ? X86::JMP64r : X86::JMP32r;
  BuildMI(MBB, MI, DL, TII.get(JmpOpc), Reg);
        
  MI->eraseFromParent();
  return true;
}

FunctionPass *llvm::createX86ProtectReturnSupport() { return new ProtectReturnSupportPass; }
