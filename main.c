#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<processthreadsapi.h>
#include<minwinbase.h>
#include<windows.h>
#include<debugapi.h>
#include<dbghelp.h>
#include<winnt.h>
#include <ntstatus.h>
#include <inttypes.h>
#include "disassembler.h"
#include "memory.h"
#include "module_ops.h"
#include "hooks.h"
ULONG_PTR k32_addr=0x0;

HANDLE hConsole;
int k;
HANDLE process=NULL;
int debug=1;
// Contains information for a single breakpoint (used as a linked list)
typedef struct _breakpoint {
    char byte; // Contains the byte that will be overwritten with INT 3
    struct _breakpoint *next; // Contains the next value in the linked list
    void *addr; // Contains the address that the breakpoint is at
} Breakpoint;
static Breakpoint *head = NULL; // Head of the linked list of breakpoints
static CREATE_PROCESS_DEBUG_INFO pInfo = {0}; // Contains information about the process creation
static PROCESS_INFORMATION pi = {0}; // Contains information about the debugged process
static int dwContinueStatus = DBG_CONTINUE; // The status for continuing execution
static char cont = 1; // This is set to 0 when the debugger exits
int size=30;


void AddBreakpoint(void *addr) {
    // Create space on the heap for this breakpoint
    Breakpoint *b = mymalloc(sizeof(Breakpoint));
    b->addr = addr;

    // Get the byte that we want to replace with INT 3 and store it in b.byte
    ReadProcessMemory(pInfo.hProcess, addr, &(b->byte), 1, NULL);

    // Insert an INT 3 (0xCC) instruction
    char byte = 0xCC;
    WriteProcessMemory(pInfo.hProcess, addr, &byte, 1, NULL);
    FlushInstructionCache(pInfo.hProcess, addr, 1);

    // Insert this into the linked list
    b->next = head;
    head = b;
}

//step
void step() {
    // Read the registers
    CONTEXT lcContext;
    lcContext.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pInfo.hThread, &lcContext);
    lcContext.EFlags |= 0x100 ; //trap. force single step and processor to stop
    SetThreadContext(pInfo.hThread, &lcContext);
    printf("TRAP FLAG SET IN THREAD %p\n",pInfo.hThread);

}



// Prints out all of the values of the registers
void PrintRegs() {
    // Read the registers
    CONTEXT lcContext;
    lcContext.ContextFlags = CONTEXT_ALL;
    GetThreadContext(pInfo.hThread, &lcContext);
    // Print out all of the values of the registers
    SetConsoleTextAttribute(hConsole,71);

    printf("RAX: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rax);
    SetConsoleTextAttribute(hConsole,71 );

    printf("RBX: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rbx);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RCX: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rcx);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RDX: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rdx);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RSP: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rsp);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RBP: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\n", lcContext.Rbp);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RSI: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rsi);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RDI: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.Rdi);
        SetConsoleTextAttribute(hConsole,71 );

    printf("R8: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.R8);
 SetConsoleTextAttribute(hConsole,71 );
    printf("R9: ");
            SetConsoleTextAttribute(hConsole,14  );
printf("0x%p\t\t", lcContext.R9);
 SetConsoleTextAttribute(hConsole,71 );
    printf("R10: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\n", lcContext.R10);
        SetConsoleTextAttribute(hConsole,71 );

    printf("R11: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.R11);
        SetConsoleTextAttribute(hConsole,71 );

    printf("R12: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.R12);
        SetConsoleTextAttribute(hConsole,71 );

    printf("R13: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.R13);
        SetConsoleTextAttribute(hConsole,71 );

    printf("R14: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.R14);
        SetConsoleTextAttribute(hConsole,71 );

    printf("R15: ");
            SetConsoleTextAttribute(hConsole,14 );
printf("0x%p\t\t", lcContext.R15);
        SetConsoleTextAttribute(hConsole,71 );

    printf("RIP: ");
    SetConsoleTextAttribute(hConsole,14 );

    printf("0x%p\n", lcContext.Rip);
        SetConsoleTextAttribute(hConsole,7 );

}


// Allows the user to type in commands into the debugger
void ProcessCommands() {
    char *cmd = mymalloc(200); // The command that the user types in
    while(strncmp(cmd, "continue", 8) != 0 && strncmp(cmd, "cont", 4) != 0) {
        printf("> ");
        fgets(cmd, 200, stdin); // Read a line

        if(strncmp(cmd, "registers", 9) == 0 || strncmp(cmd, "regs", 4) == 0) {
            PrintRegs(); // Prints out all of the values of the registers
        }        if(strncmp(cmd, "hook", 4) == 0 ) {
            strtok(cmd, " "); // The value after the space should be the address in hex

            alloc4hook(pInfo.hProcess,(void *) strtoll(strtok(NULL, " "), 0, 16)); // Prints out all of the values of the registers
        } else if(strncmp(cmd, "ba ", 3) == 0 ) {
            strtok(cmd, " "); // The value after the space should be the address in hex
            AddBreakpoint((void *) strtoll(strtok(NULL, " "), 0, 16)); // Adds a breakpoint at that address
        } else if(strncmp(cmd, "mod", 3) == 0 ) {
            printf("kernel32.dll @ 0x%p",k32_addr);
            //todo support all modules
        }else if(strncmp(cmd, "ia ", 3) == 0 ) {
            strtok(cmd, " "); // The value after the space should be the address in hex
            PULONG_PTR proc= (PULONG_PTR) 0x1;
            char buffer[strlen(cmd+3)];
            memcpy(buffer, cmd+3, strlen(cmd+3)-1);
            char *p = buffer;
            printf("Looking for %s\n",p);
            proc=RDrvGetProcAddress((ULONG_PTR) k32_addr, p, proc);
            printf("Function @ 0x%p\n",proc);
        } else if(strncmp(cmd, "b ", 2) == 0) {
            strtok(cmd, " "); // The value after the space should be the address in hex
            PULONG_PTR proc= (PULONG_PTR) 0x1;
            char buffer[strlen(cmd+2)];
            memcpy(buffer, cmd+2, strlen(cmd+2)-1);
            char *p = buffer;
            printf("Looking for %s\n",p);
            proc=RDrvGetProcAddress((ULONG_PTR) k32_addr, p, proc);
            printf("Breakpoint @ 0x%p",proc);
            AddBreakpoint(proc);
        }  else if((strncmp(cmd, "s", 1) == 0) || (strncmp(cmd, "\n", 1) == 0)) {
            CONTEXT lcContext;


            step();

            //sorry for this fucking hack!!!!!
            //if program doesnt continue here it wont trap and
            //thread will be forced to continue
            //fucking race condition in debug handle loop
            dwContinueStatus = DBG_CONTINUE;


            break;
        } else if((strncmp(cmd, "trace", 1) == 0)) {
            void* stack[8000];
            int frames = CaptureStackBackTrace(0, 8000, stack, NULL);

        } else if(strncmp(cmd, "da ", 3) == 0) {
            strtok(cmd, " ");
            char *a = strtok(NULL, " "); // The value after the first space should be the address in hex
            char *b = strtok(NULL, " "); // The value after the second space should be the number of bytes to read in decimal
            long long addr = strtoll(a, 0, 16);
            printf("Disassembling @ address 0x%llx...\n", addr);
            disassemble(pInfo.hProcess,(void *) addr); // Read from the given memory address
        }
        else if(strncmp(cmd, "mem ", 4) == 0) {
            strtok(cmd, " ");
            char *a = strtok(NULL, " "); // The value after the first space should be the address in hex
            char *b = strtok(NULL, " "); // The value after the second space should be the number of bytes to read in decimal
            ReadMemory(pInfo.hProcess,a, atoi(b)); // Read from the given memory address
        } else if(strncmp(cmd, "quit", 4) == 0 || strncmp(cmd, "q", 1) == 0 || strncmp(cmd, "exit", 4) == 0) {
            printf("Debugger will now exit.\n"); // Exit the program
            exit(0);
        } else if(strncmp(cmd, "help", 4) == 0) {
            printf("continue: Continues execution.\n");
            printf("registers: Prints out the values of all registers.\n");
            printf("ba <addr>: Sets a breakpoint at a given address.\n");
            printf("ia <name>: Displays address of a given name in k32 only.\n");
            printf("b <name>: Sets a breakpoint at a given name in k32 only.\n");
            printf("da <addr>: Disassemble 30 bytes at address.\n");
            printf("hook <addr>: Trampoline hook at address. Detour is nop\n");
            printf("TODO mod: See all loaded modules information. Only k32 for now\n");
            printf("s : Step by trap flag.\n");
            printf("TODO trace : Stack trace.\n");
            printf("mem <addr> <bytes>: Reads a given number of bytes from a given memory address.\n");
            printf("quit: Closes the debugger.\n");
        }
    }

}

void ProcessBreakpoint(DEBUG_EVENT debug_event) {
    if(head != NULL) { // Do nothing if the head of the breakpoint linked list is NULL
        // Get the value of RIP
        CONTEXT lcContext;
        lcContext.ContextFlags = CONTEXT_ALL;
        GetThreadContext(pInfo.hThread, &lcContext); // Obtains the thread context (which contains info about registers)
        lcContext.Rip--; // Move RIP back one byte (RIP would've moved forward as soon as it read INT 3)

        // Find the breakpoint in the linked list, obtain the byte that was originally there and its address, and delete the node from the linked list
        char byte = 0;
        void *addr = NULL;
        char found = 1; // This is set to zero if we did not find the correct byte
        if(head->addr == (void *) lcContext.Rip) { // Triggered if the head is the breakpoint we're looking for
            byte = head->byte; // Save the byte
            addr = head->addr; // Save the address

            // Delete the head
            Breakpoint *del = head;
            head = head->next;
            free(del);
        } else { // Else, loop until we find the correct breakpoint
            Breakpoint *b = head;
            while(b->next != NULL && b->next->addr != (void *) lcContext.Rip) {
                b = b->next;
            }
            if(b->next != NULL) {
                byte = b->next->byte; // Save the byte
                addr = b->next->addr; // Save the address

                // delete the correct node
                Breakpoint *del = b->next;
                b->next = del->next;
                free(del);
            } else { // If this else statement hits, then we did not find the breakpoint in the linked list, and we will just ignore it
                found = 0;
            }
        }
        if(found) {
            // Indicate that we have hit a breakpoint
            dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED; // The debuggee should not handle this exception
            SetConsoleTextAttribute(hConsole,12);

            printf("Hit a breakpoint!\n");
            SetConsoleTextAttribute(hConsole,7);

            // Apply the change to RIP (which was moved one byte backwards earlier)
            SetThreadContext(pInfo.hThread, &lcContext);

            // Replace the INT 3 instruction with the byte that was originally there
            WriteProcessMemory(pInfo.hProcess, addr, &byte, 1, NULL);
            FlushInstructionCache(pInfo.hProcess, addr, 1);
            char instr[size];
            ReadProcessMemory(pInfo.hProcess, addr, &instr, size, NULL);

            disassemble(pInfo.hProcess,addr);
            ProcessCommands(); //do not move this into main loop. There is some race condition
        }
    }
}

// Called when the debuggee process is being created
void ProcessCreation(DEBUG_EVENT debug_event) {
    // Obtain information about the process's creation
    pInfo = debug_event.u.CreateProcessInfo;

    // Add a breakpoint at the start address
    printf("Setting a breakpoint at the start address...\n");
    AddBreakpoint(pInfo.lpStartAddress);
}

// Called when the debuggee outputs a string
void OutputString(DEBUG_EVENT debug_event) {
    // Obtains information (including a pointer) about the string being printed
    // Note that this pointer is only valid on the debuggee's process, but not on the debugger's process
    // So we'll have to read from the debuggee's process and copy that string's value into a string in our process
    OUTPUT_DEBUG_STRING_INFO DebugString = debug_event.u.DebugString;

    // Create space on the heap to store the string being printed
    char* str = mymalloc(DebugString.nDebugStringLength);

    // Read the string from the debuggee's memory and print it
    ReadProcessMemory(pi.hProcess, DebugString.lpDebugStringData, str, DebugString.nDebugStringLength, NULL);
    printf("Debug String Received: %s\n", str);

    // Free the heap
    free(str);
    str = NULL;
}

void cbLoadDllEvent(const LOAD_DLL_DEBUG_INFO loadDll)
{
    hConsole=GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole,10);


    printf("DLL loaded at 0x%p\n",loadDll.lpBaseOfDll);
    long long int temp=PrintDLLNameFromAddress(loadDll.lpBaseOfDll);
    if(temp!=0x0)
    {
        //shit solution for a shit problem. too complicated to pass by reference between different modules.
        //dont want to gget killed for access violation!!!
        k32_addr=PrintDLLNameFromAddress(loadDll.lpBaseOfDll);
        //TODO make this linked list of all modules instead of this

    }
    SetConsoleTextAttribute(hConsole,7);

}

//this is for buggy windows sending double process start sometimes. Keep interface clean
int start=0;

// Called when the debuggee receives an exception
void ProcessException(DEBUG_EVENT debug_event) {
    CONTEXT lcContext;

    DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
    //printf("%lu\n",code);


    if(start!=0)
        PrintRegs();
    else start++;
    switch(code) {
        case STATUS_BREAKPOINT: // Called when the exception was caused by a breakpoint
            ProcessBreakpoint(debug_event);
            //            ProcessCommands(); needs to stay inside!!! fucking race condition
            break;
        case EXCEPTION_SINGLE_STEP: // Called when the exception was caused by a single step for trap flag

            lcContext.ContextFlags = CONTEXT_ALL;
            GetThreadContext(pInfo.hThread, &lcContext); // Obtains the thread context (which contains info about registers)
            printf("RIP: 0x%llx\n", lcContext.Rip);
            disassemble(pInfo.hProcess,(void *) lcContext.Rip);
            ProcessCommands(); // Allow the user to type in commands into the debugger

            break;
        default:
            printf("Exception %d (0x%x) received.\n", code, code);
            ProcessCommands(); // Allow the user to type in commands into the debugger
            break;
    }
}

// Called when the debuggee exits
void ExitDebuggeeProcess(DEBUG_EVENT debug_event) {
    printf("Process exited with code %d (0x%x).\n", debug_event.u.ExitProcess.dwExitCode, debug_event.u.ExitProcess.dwExitCode);
    cont = 0; // Stop the debugger
}


void ProcessDebugEvent(DEBUG_EVENT debug_event) {
    // Reset the continue status (in case it was changed while processing an exception)
        dwContinueStatus = DBG_CONTINUE;

    // Call the correct function depending on what the event code is
    switch(debug_event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: // Called when the debuggee process is first created
            ProcessCreation(debug_event);
            break;
        case OUTPUT_DEBUG_STRING_EVENT: // Called when a string is sent to the debugger for display
            OutputString(debug_event);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            cbLoadDllEvent(debug_event.u.LoadDll);
            break;
        case EXCEPTION_DEBUG_EVENT: // Called whenever any exception occurs in the process being debugged
            ProcessException(debug_event);
            break;
        case EXIT_PROCESS_DEBUG_EVENT: // Called when the debuggee process exits
            ExitDebuggeeProcess(debug_event);
            break;
    }
}


int main(int argc, char** argv) {
/*
    hConsole=GetStdHandle(STD_OUTPUT_HANDLE);
    for(k=1;k<255;k++)
    {
        SetConsoleTextAttribute(hConsole,k);
        printf("%3d %s\n",k,"idiot");
    }
    return 0;*/
    if(argc<2){
        printf("Give a program");
        return 0;

    }
    // Initialize some variables
    STARTUPINFO si; // Contains startup information about the debugged process
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    int flags=DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS |CREATE_NEW_CONSOLE;
    // Create the process to debug
    CreateProcessA(argv[1], NULL, NULL, NULL, 0, flags, NULL, NULL, &si, &pi);

    process=pi.hProcess;
    // Process debugging events
    DEBUG_EVENT debug_event = {0};
    while(cont) {
        if(!WaitForDebugEvent(&debug_event, INFINITE)) {
            break; // Break the loop if the function fails
        }
        ProcessDebugEvent(debug_event); // User-defined function that will process the event
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus); // Continue execution
    }

    // Exit the debugger
    printf("Debugger will now exit.\n");
    return 0;
}