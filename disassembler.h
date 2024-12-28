//
// Created by BLUE_gigi on 12/01/2024.
//
#include <inttypes.h>

#include <memoryapi.h>
#include <stdio.h>
#include "Zydis.h"

void disassemble(HANDLE proc,void* rip);
ZydisDisassembledInstruction steal_one(HANDLE proc,void* rip);
uint32_t WriteAbsoluteJump64(HANDLE process, void* absJumpMemory, void* addrToJumpTo);