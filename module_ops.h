//
// Created by BLUE_gigi on 12/01/2024.
//

#ifndef BB_MODULE_OPS_H
#define BB_MODULE_OPS_H
#include <windows.h>
#include <stdio.h>

void* RDrvGetProcAddress(
        IN ULONG_PTR pModuleBase,
        IN PCSTR szProcName,
        OUT PULONG_PTR pProcAddress
);;

ULONG_PTR PrintDLLNameFromAddress(void* address);
#endif //BB_MODULE_OPS_H
