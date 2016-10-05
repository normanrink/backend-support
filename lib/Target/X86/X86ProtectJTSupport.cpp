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


namespace {
class ProtectJTSupportPass : public MachineFunctionPass {
  static char ID;

  const char *getPassName() const override { return "X86 Support for return instruction protection"; }

public:
  ProtectJTSupportPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &Func) override;

  bool handleInst(MachineBasicBlock &MM, MachineInstr *MI);
};

char ProtectJTSupportPass::ID = 0;
}

bool ProtectJTSupportPass::runOnMachineFunction(MachineFunction &Func) {
  if (!Func.protectJT())
    return false;

  bool modified = false;
  
  for (MachineFunction::iterator MBB = Func.begin(); MBB != Func.end(); MBB++) {
    MachineBasicBlock::iterator MI = MBB->begin();
    while(MI != MBB->end()) {
      MachineBasicBlock::iterator NMI = std::next(MI);

      modified |= handleInst(*MBB, MI);
  
      MI = NMI;
    }
  }

  return modified;
}

bool ProtectJTSupportPass::handleInst(MachineBasicBlock &MBB, MachineInstr *MI) {
  if (!MI->isBranch())
    return false;
    
  // Branches to addresses in jump tables are apparently treated as conditional branches.
  // Note, however, that general conditional branches cannot be handled here since checking
  // for errors resets the machine status flags.
      
  // From 'X86InstrBuilder.h', ca. line 86:
  // Memory references are always represented with five values:
  // Reg, 1, NoReg, 0, NoReg to the instruction.
  if (MI->getNumOperands() != 5)
    return false;

  MachineOperand &Reg0 = MI->getOperand(0),
                 &Reg2 = MI->getOperand(2),
                 &Reg4 = MI->getOperand(4);
  MachineOperand &Imm1 = MI->getOperand(1);
  MachineOperand &JTI3 = MI->getOperand(3);

  if (!Reg0.isReg()) return false;
  if (!Reg2.isReg()) return false;
  if (!Reg4.isReg()) return false;
  if (!Imm1.isImm()) return false;
  if (!JTI3.isJTI()) return false;
  
  MI->dump();

  MachineFunction &MF = *MBB.getParent();
  const DebugLoc &DL = MI->getDebugLoc();

  const TargetInstrInfo &TII = *MF.getTarget().getInstrInfo();
  const X86Subtarget &STI = MF.getTarget().getSubtarget<X86Subtarget>();
  
  const TargetRegisterClass *RC = STI.is64Bit() ? &X86::GR64RegClass
                                                : &X86::GR32RegClass;
  unsigned VReg = MF.getRegInfo().createVirtualRegister(RC);
  
  unsigned LoadOpc = STI.is64Bit() ? X86::MOV64rm : X86::MOV32rm;
  unsigned CmpOpc = STI.is64Bit() ? X86::CJE64rm : X86::CJE32rm;

  MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(LoadOpc), VReg);
  MIB.addReg(Reg0.getReg()).addImm(Imm1.getImm()).addReg(Reg2.getReg())
     .addJumpTableIndex(JTI3.getIndex()).addReg(Reg4.getReg());
  MIB->setMemRefs(MI->memoperands_begin(), MI->memoperands_end());
  
  MIB = BuildMI(MBB, MI, DL, TII.get(CmpOpc)).addReg(VReg);
  MIB.addReg(Reg0.getReg()).addImm(Imm1.getImm()).addReg(Reg2.getReg())
     .addJumpTableIndex(JTI3.getIndex()+1).addReg(Reg4.getReg());
  MIB->setMemRefs(MI->memoperands_begin(), MI->memoperands_end());
  
  unsigned JmpOpc = STI.is64Bit() ? X86::JMP64r : X86::JMP32r;
  BuildMI(MBB, MI, DL, TII.get(JmpOpc)).addReg(VReg, RegState::Kill);
        
  MI->eraseFromParent();
  return true;
}

FunctionPass *llvm::createX86ProtectJTSupport() { return new ProtectJTSupportPass; }

