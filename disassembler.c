//
// Created by BLUE_gigi on 12/01/2024.
//
#include <inttypes.h>

#include <memoryapi.h>
#include <stdio.h>
#include "Zydis.h"
#include "memory.h"

void disassemble(HANDLE proc,void* rip){



    char instr[30];
    if(!ReadProcessMemory(proc, (void *) rip, &instr, 15, NULL))
        printf("Read memory is fucked\n");

    // The runtime address (instruction pointer) was chosen arbitrarily here in order to better
    // visualize relative addressing. In your actual program, set this to e.g. the memory address
    // that the code being disassembled was read from.
    ZyanU64 runtime_address = (ZyanU64) rip;

    /*for(int i=0;i<size;i++)
    printf("\\x%hhx",instr[i]);*/
    // Loop over the instructions in our buffer.
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
            /* runtime_address: */ runtime_address,
            /* buffer:          */ instr + offset,
            /* length:          */ sizeof(instr) - offset,
            /* instruction:     */ &instruction
    ))) {
        HANDLE hConsole=GetStdHandle(STD_OUTPUT_HANDLE);

        SetConsoleTextAttribute(hConsole,78);

        printf("0x%016" PRIx64 "  ", runtime_address);
        SetConsoleTextAttribute(hConsole,10);

        printf("|%-35s|", instruction.text);
        SetConsoleTextAttribute(hConsole,3);
        for(int i=0;i<instruction.info.length;i++)
        {
            char a=*(instr+offset+i);
            if(a!=0)
                printf("%hhx ",a);
            else
                printf("00 ");
        }
        SetConsoleTextAttribute(hConsole,7);


        printf("\n");
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
    }


}

ZydisDisassembledInstruction steal_one(HANDLE proc,void* rip){

    DWORD oldProtect;
    VirtualProtect(rip, 15, PAGE_EXECUTE_READWRITE, &oldProtect);
    char instr[30];
    if(!ReadProcessMemory(proc, (void *) rip, &instr, 15, NULL))
        printf("Read memory is fucked\n");

    // The runtime address (instruction pointer) was chosen arbitrarily here in order to better
    // visualize relative addressing. In your actual program, set this to e.g. the memory address
    // that the code being disassembled was read from.
    ZyanU64 runtime_address = (ZyanU64) rip;

    /*for(int i=0;i<size;i++)
    printf("\\x%hhx",instr[i]);*/
    // Loop over the instructions in our buffer.
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;
    ZydisDisassembleIntel(
            /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
            /* runtime_address: */ runtime_address,
            /* buffer:          */ instr + offset,
            /* length:          */ sizeof(instr) - offset,
            /* instruction:     */ &instruction
    );

    HANDLE hConsole=GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole,78);

    printf("0x%016" PRIx64 "  ", runtime_address);
    SetConsoleTextAttribute(hConsole,10);

    printf("|%-35s|", instruction.text);
    SetConsoleTextAttribute(hConsole,3);

    for(int i=0;i<instruction.info.length;i++)
        {
            char a=*(instr+offset+i);
            if(a!=0)
                printf("%hhx ",a);
            else
                printf("00 ");


        }
    SetConsoleTextAttribute(hConsole,7);

        printf("\n");
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
        return instruction;


}

uint32_t WriteAbsoluteJump64(HANDLE process, void* absJumpMemory, void* addrToJumpTo)
{

    //this writes the absolute jump instructions into the memory allocated near the target
    //the E9 jump installed in the target function (GetNum) will jump to here
    uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
                                      0x41, 0xFF, 0xE2 }; //jmp r10

    uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
    memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));

    WriteProcessMemory(process, absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions), NULL);
    return sizeof(absJumpInstructions);
}