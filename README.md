# Shellcode for creating a minidump-file (.dmg) of lsass.exe

**Purpose:** To avoid putting mimikatz directly on the system. The shellcode can be incorporated into different projects/exploits etc. 

**Limitations:** The SeDebugPrivilege has to be enabled before using the shellcode. *(Hint: Powershell enables SeDebugPrivileged by default if the current user is allowed to use it i.e the local administrator).*  

**Where:** A file named lsass.dmp is created in the *current directory* 

**Fun-facts:** The Win32 API used: MiniDumpWriteDump is located within dbgcore.dll and not dbghelp.dll. 
