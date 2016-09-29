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

  bool handleCallInst(MachineInstr *MI);
  bool handleReturnInst(MachineBasicBlock &MM, MachineInstr *MI);
};

char ProtectReturnSupportPass::ID = 0;
}

static bool isReturnBlock(const MachineBasicBlock *MBB) {
  for (auto MI = MBB->begin(), ME = MBB->end(); MI != ME; MI++)
    if (MI->isReturn())
      return true;

  return false;
}

bool ProtectReturnSupportPass::runOnMachineFunction(MachineFunction &Func) {
  if (!Func.protectReturnPtr())
    return false;

  bool modified = false;
  
  if (!Func.getName().equals("main")) {
    // Store the contents of register 'r11' (i.e. the return address) onto
    // the stack immediately after entering the function 'Func':
    const TargetInstrInfo &TII = *Func.getTarget().getInstrInfo();
    const X86Subtarget &STI = Func.getTarget().getSubtarget<X86Subtarget>();

    unsigned Reg = STI.is64Bit() ? X86::R11 : X86::EDX;
    unsigned PushOpc = STI.is64Bit() ? X86::PUSH64r : X86::PUSH32r;

    MachineBasicBlock *MBB = Func.begin();
    MachineBasicBlock::iterator MI = MBB->begin();

    const DebugLoc &DL = MI->getDebugLoc();
    BuildMI(*MBB, MI, DL, TII.get(PushOpc)).addReg(Reg, RegState::Kill);
 
    modified = true;
 
    // Introduce a check of the return address immediately before return
    // instructions: 
    for (auto MBBI = Func.begin(), MBBE = Func.end(); MBBI != MBBE; MBBI++) {
      if (!isReturnBlock(MBBI))
        continue;
      
      modified |= handleReturnInst(*MBBI, MBBI->getFirstTerminator());
    }
  }

 
  SmallVector<MachineInstr*, 16> worklist;

  for (auto MBBI = Func.begin(), MBBE = Func.end(); MBBI != MBBE; MBBI++) {
    for (auto MI = MBBI->begin(), ME = MBBI->end(); MI != ME; MI++)
      if (MI->isCall()) worklist.push_back(MI);
  }
  while (!worklist.empty()) {
    MachineInstr *mi = worklist.pop_back_val();
    modified |= handleCallInst(mi);
  }
  

  return modified;
}

bool ProtectReturnSupportPass::handleCallInst(MachineInstr *MI) {
  if (!MI->isCall() || MI->isReturn())
    return false;
      
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction &MF = *MBB->getParent();
  const DebugLoc &DL = MI->getDebugLoc();

  const X86RegisterInfo *RegInfo =
      static_cast<const X86RegisterInfo *>(MF.getTarget().getRegisterInfo());
  const TargetInstrInfo &TII = *MF.getTarget().getInstrInfo();
  const X86Subtarget &STI = MF.getTarget().getSubtarget<X86Subtarget>();

  /* On X86 the size of the opcode for the call instruction is not known until
   * object code is emitted. (The size of the opcoded depends, e.g., on what
   * arguments the call instruction receives.)
   * If the size of the opcode could be deduced from the return value of
   * 'MI->getOpcode()', one caould make do with a sequence of if/else
   * statements like this:

      unsigned CallOpcSize = 0;
      
      if (MI->getOpcode() == X86::CALL64pcrel32) {
        CallOpcSize = 5;
      } else if (MI->getOpcode() == X86::CALL64r) {
        ...
      } else  {
      DEBUG({dbgs() << "unhandled call opcode\n";
             MI->dump();
             dbgs() << "no. operands: " << MI->getNumOperands() << "\n";});
      llvm_unreachable("unhandled call opcode");
      }
      
   * The determined size of the opcode could then be used to determine the
   * return address like so:

      addRegOffset(BuildMI(MBB, MI, DL, TII.get(X86::LEA64r), X86::R11),
                   X86::RIP, false, CallOpcSize);

   * Unfortunately, since it is not possible to use a simple sequence of
   * if/else statements to deduce the opcode size, we have to introduce a
   * label immediately after the call instruction. The address of the label is
   * then equal to the return address, which is put on the stack by the call
   * instruction. The value of the label, i.e. the return address, is then
   * placed in the 'r11' register.
   *
   * Introducing the new label is involved since it requires that a new basic
   * block is introduced. Instructions must then be transferred to the new
   * basic block, and successors and predecessors must be set up correctly.
   * 
   * The basic block 'MBB' is split up after the call instruction 'MI'.
   * The label of the new basic block 'NewMBB' thus ends up at the correct
   * address, i.e. immediately after the call. The call instruction must then
   * return to the beginning of 'NewMBB', which means that control must fall
   * through from 'MBB' to 'NewMBB'.
   */

  MachineBasicBlock *NewMBB = MF.CreateMachineBasicBlock(MBB->getBasicBlock());
  // Transfer instructions to the new basic block 'NewBB':
  MachineBasicBlock::iterator MBBI = MI;
  ++MBBI;
  while (MBBI != MBB->end()) {
    MachineInstr *mi = MBBI;
    MachineBasicBlock::iterator NextMBBI = std::next(MBBI);

    MBB->remove(mi);
    NewMBB->insert(NewMBB->end(), mi);

    MBBI = NextMBBI;
  }
  // Add 'NewBB' to the function 'MF' (and assign a number to 'NewMBB'):
  MF.push_back(NewMBB);
  NewMBB->setNumber(MF.addToMBBNumbering(NewMBB));
  // Move 'NewMBB' to immediately after 'MBB' since control must fall through
  // from 'MBB' to 'NewMBB':
  NewMBB->moveAfter(MBB);
  // Hook up successors and predecessors properly:
  NewMBB->transferSuccessors(MBB);
  // This also takes care of the predecessors of 'NewMBB'.
  MBB->addSuccessor(NewMBB);
  
  // HACK: This ensures that the 'AsmPrinter' emits the label at the start
  // of the new basic block 'NewMBB':
  NewMBB->setIsLandingPad();
  
  // Move the address of the start of 'NewBB' to register 'r11' immediately
  // before the call instruction 'MI':
  unsigned Reg = STI.is64Bit() ? X86::R11 : X86::EDX;
  unsigned MovOpc = STI.is64Bit() ? X86::MOV64ri : X86::MOV32ri;
  BuildMI(*MBB, MI, DL, TII.get(MovOpc), Reg).addMBB(NewMBB);

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
  
  if (MI->getOpcode() == X86::TAILJMPd64 || MI->getOpcode() == X86::TAILJMPm64 ||
      MI->getOpcode() == X86::TAILJMPr64) {
    // TODO: Figure out if one can test for tail jumps by "isReturn() && isCall()"
    // of "isReturn() && isBranch()" or similar combination.

    // For tail jumps, the duplicated return address from the stack must be put into
    // the 'r11' register:
    BuildMI(MBB, MI, DL, TII.get(PopOpc), Reg);
    return true;
  }
  DEBUG(MI->dump()); // Only "true" return instructions should reach this point.

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

