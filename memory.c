//
// Created by BLUE_gigi on 12/01/2024.
//

#include <memoryapi.h>
#include <stdio.h>
#include <sysinfoapi.h>
#include <stdint.h>
#include "memory.h"

void *mymalloc(int size) {
    void *mem = malloc(size);
    if(mem == NULL) {
        printf("Error allocating memory on the heap.\n");
        exit(0);
    }
    return mem;
}


void* AllocatePageNearAddressRemote(HANDLE handle, void* targetAddr)
{

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

    uint64_t startAddr = ((uint64_t)targetAddr); //round down to nearest page boundary
    uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

    uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

    uint64_t pageOffset = 1;
    while (1)
    {
        uint64_t byteOffset = pageOffset * PAGE_SIZE;
        uint64_t highAddr = startPage + byteOffset;
        uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

        int needsExit = highAddr > maxAddr && lowAddr < minAddr;

        if (highAddr < maxAddr)
        {
            void* outAddr = VirtualAllocEx(handle, (void*)highAddr, (size_t)PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr)
                return outAddr;
        }

        if (lowAddr > minAddr)
        {
            void* outAddr = VirtualAllocEx(handle, (void*)lowAddr, (size_t)PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr != NULL)
                return outAddr;
        }

        pageOffset++;

        if (needsExit)
        {
            break;
        }
    }
    printf("done @ 0x%p\n",startAddr);

    return NULL;
}


void ReadMemory(HANDLE proc,char *addr_hex, int n) {
    // Convert the address from a hex string into a DWORD64
    long long addr = strtoll(addr_hex, 0, 16);
    printf("Reading memory from address 0x%llx...\n", addr);

    // Read n bytes from the given memory address
    char *buf = mymalloc(n);
    ReadProcessMemory(proc, (LPCVOID) addr, buf, n, NULL);

    // Loop through each byte in the buffer and print it out
    for(int i = 0; i < n; i++) {
        printf("0x%hhx ", buf[i]);
    }
    printf("\n");
}
