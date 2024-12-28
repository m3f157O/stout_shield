cmake_minimum_required(VERSION 3.25)


project(BB C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXE_LINKER_FLAGS "-static")
add_executable(BB main.c Zydis.c Zydis.h Zydis.h memory.c memory.h  hooks.c disassembler.c disassembler.h module_ops.c module_ops.h hooks.h)
