
#include <stdio.h>
#include "memory.h"
#include "disassembler.h"


void alloc4hook(HANDLE proc,void* target_function){
    printf("allocating near 0x%p\n", target_function);
    //void* exec= VirtualAllocEx(pInfo.hProcess, NULL, 8, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    //get page near for things easier
    void *hook = AllocatePageNearAddressRemote(proc, target_function);//VirtualAllocEx(proc, NULL, 8, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    //example hook code
    int hook_code_size=8;

    printf("[1]###############################\nHook start @ 0x%p\n",hook);
    //address of target+nops
    WriteProcessMemory(proc, hook, "\x90\x90\x90\x90\x90\x90\x90\x90", hook_code_size, NULL);
    printf("Hook code written\n################################\n",hook);


    printf("[2]###############################\nStealing instructions for trampoline\n");
    //steal one instruction, replace with nops for now, later with relative jump to *hook address (5 bytes) TODO ENSURE INSTRUCTION STEAL IS >5
    ZydisDisassembledInstruction disassembled_instr=steal_one(proc, target_function);
    char stolen_bytes[10];
    int total_stolen_bytes=0;


    if(disassembled_instr.info.length<5)
    {
        total_stolen_bytes=disassembled_instr.info.length;
        do{
            printf("Total stolen bytes: %d\n",total_stolen_bytes);

            ZydisDisassembledInstruction dis=steal_one(proc, target_function+total_stolen_bytes);
            total_stolen_bytes+=dis.info.length;
        }while(total_stolen_bytes<5);
    }
    else
        total_stolen_bytes=disassembled_instr.info.length;
    printf("Total stolen bytes: %d\n",total_stolen_bytes);


    //EFFECTIVE STEAL
    ReadProcessMemory(proc, (void *) target_function, &stolen_bytes, total_stolen_bytes, NULL);
    WriteProcessMemory(proc, target_function, "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", total_stolen_bytes, NULL);
    printf("Instructions stolen, replaced with nops\n");
    printf("Writing trampoline @ 0x%p\n",hook+hook_code_size);

    WriteProcessMemory(proc, hook+hook_code_size, stolen_bytes, total_stolen_bytes, NULL);
    printf("Trampoline return @ 0x%p\n", target_function + total_stolen_bytes);

    printf("Trampoline built\n################################\n");




    //write trampoline after hook code

    printf("[3]###############################\nWriting return jump for trampoline\n");

    printf("Writing return jump @ 0x%p\n", hook + hook_code_size + total_stolen_bytes);

    //write absolute jump to trampoline return
    WriteAbsoluteJump64(proc, hook + hook_code_size + total_stolen_bytes, target_function + total_stolen_bytes);
    steal_one(proc, hook + hook_code_size + total_stolen_bytes);
    steal_one(proc, hook + hook_code_size + total_stolen_bytes+10);
    printf("Return jump built\n################################\n");

    printf("[4]###############################\nInstalling hook\n");

    //install the hook
    uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
    printf("Calculating relative jump for hook installation @ 0x%p-(0x%p+%d)\n",hook,target_function,5);

    const int32_t relAddr = (int32_t)((uint64_t)hook - ((uint64_t)target_function + sizeof(jmpInstruction)));
    printf("Hook jump offset @0x%p\n",relAddr);

    memcpy(jmpInstruction + 1, &relAddr, 4);
    WriteProcessMemory(proc, target_function, jmpInstruction, sizeof(jmpInstruction), NULL);
    steal_one(proc,target_function);
    printf("Hook installed\n################################\n");

}
