//
// Created by BLUE_gigi on 12/01/2024.
//
#include <windows.h>
#ifndef BB_MEMORY_H
#define BB_MEMORY_H
void *mymalloc(int size);
void* AllocatePageNearAddressRemote(HANDLE handle, void* targetAddr);
void ReadMemory(HANDLE proc,char *addr_hex, int n);
#endif //BB_MEMORY_H
