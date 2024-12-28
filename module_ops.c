//
// Created by BLUE_gigi on 12/01/2024.
///

#include <windows.h>
#include "module_ops.h"
void* RDrvGetProcAddress(
        IN ULONG_PTR pModuleBase,
        IN PCSTR szProcName,
        OUT PULONG_PTR pProcAddress
)
{
    if(!pModuleBase)	return (void *) 1;
    if(!szProcName)		return (void *) 2;
    if(!pProcAddress)	return (void *) 3;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return (void *) 4;

    PIMAGE_NT_HEADERS32 pNtHdrs32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pModuleBase + pDosHeader->e_lfanew);
    PIMAGE_NT_HEADERS64 pNtHdrs64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pModuleBase + pDosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

    //WOW64 module
    if(pNtHdrs32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pModuleBase + pNtHdrs32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    else if(pNtHdrs64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { //Native x64 module
        pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pModuleBase + pNtHdrs64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PULONG	pAddressOfFunctions = (PULONG)(pExportDir->AddressOfFunctions + (PUCHAR)pModuleBase);
        PULONG	pAddressOfNames     = (PULONG)(pExportDir->AddressOfNames + (PUCHAR)pModuleBase);
        PUSHORT	pAddressOfOrdinals  = (PUSHORT)(pExportDir->AddressOfNameOrdinals + (PUCHAR)pModuleBase);
        ULONG	numberOfNames       = pExportDir->NumberOfNames;

        for(ULONG i = 0; i < numberOfNames; i++) {
            PCSTR pszName = (PCSTR)((PUCHAR)pModuleBase + pAddressOfNames[i]);
            USHORT ordinal = pAddressOfOrdinals[i];
            //printf("Function %s\n",pszName);
            //printf("%p\n",pAddressOfFunctions[i]+(PUCHAR)pModuleBase);

            if(!strcmp(pszName, szProcName)) {
                //printf("%d\n",ordinal);
                // Read memory from the target process
                int value = 0;
                SIZE_T bytesRead = 0;

                //AddBreakpoint(pProcAddress);
                // Close the target process handle
                return (LPVOID)(pAddressOfFunctions[ordinal] + (PUCHAR)pModuleBase);
            }
        }
        return (void *) 0;
    }
}



ULONG_PTR PrintDLLNameFromAddress(void* address) {
    HMODULE moduleHandle;
    TCHAR moduleName[MAX_PATH];
    ULONG_PTR k32_addr=0x0;

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCTSTR)(address), &moduleHandle) != 0)
    {
        if (GetModuleFileName(moduleHandle, moduleName, sizeof(moduleName)) != 0) {
            HANDLE hConsole=GetStdHandle(STD_OUTPUT_HANDLE);

            SetConsoleTextAttribute(hConsole,15);
            printf("Module name: ");
            SetConsoleTextAttribute(hConsole,11);
            printf("%s\n",moduleName);

            if(strncmp(moduleName,"C:\\Windows\\System32\\KERNEL32.DLL",27) == 0)
            {
                    SetConsoleTextAttribute(hConsole,12);

                k32_addr=(ULONG_PTR)address;
                printf("Kernel32 found: %p\n", k32_addr);

                return k32_addr;

            }

        } else {
            printf("Failed to get module file name\n");
        }

        // Release the module handle
        FreeLibrary(moduleHandle);
    } else {
        printf("Failed to get module handle\n");
    }
    return (ULONG_PTR) NULL;
}
