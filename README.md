# Shellcode for creating a minidump-file (.dmg) of lsass.exe

Purpose: To avoid putting mimikatz directly on the system. The shellcode can be incorporated into different projects/exploits etc. 

Limitations: The SeDebugPrivilege has to be enabled before using the shellcode. (Hint: Powershell enables SeDebugPrivileged by default if the current user is allowed to use it). 
