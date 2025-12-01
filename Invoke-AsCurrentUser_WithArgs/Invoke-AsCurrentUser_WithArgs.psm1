<#
.SYNOPSIS
    PowerShell module for executing scripts in the context of the currently logged-in user.
.DESCRIPTION
    This module provides functionality to execute PowerShell scriptblocks as the currently
    logged-in user from a SYSTEM context (such as during Intune deployments, SCCM task sequences,
    or scheduled tasks running as SYSTEM).
    Key features:
    - Execute scriptblocks as the interactive user session
    - Pass arguments/variables to the remote scriptblock
    - Capture transcript output and execution results
    - Support for both Windows PowerShell 5.1 and PowerShell 7+
    - Configurable timeout handling
    - Optional stream capture (stdout/stderr)
.NOTES
    Author: Martin
    Version: 1.0.0
    Requires: Windows PowerShell 5.1 or PowerShell 7+
    Requires: Running as SYSTEM or with SeDelegateSessionUserImpersonatePrivilege
.LINK
    https://github.com/Harze2k/Invoke-AsCurrentUser_WithArgs
#>
#Requires -Version 5.1
#region Helper Functions
function Get-RunAsUserCSharpSource {
    <#
    .SYNOPSIS
        Returns the C# source code for the RunAsUser.ProcessExtensions class.
    .DESCRIPTION
        This function returns the C# source code required for creating processes
        in the context of the currently logged-in user. The code handles token
        manipulation, environment block creation, and process creation.
    .OUTPUTS
        System.String
        Returns the C# source code as a string.
    .EXAMPLE
        $csharpCode = Get-RunAsUserCSharpSource
        Add-Type -TypeDefinition $csharpCode
        Compiles the C# code and makes the RunAsUser.ProcessExtensions class available.
    .NOTES
        This is an internal function used by Invoke-AsCurrentUser_WithArgs.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace RunAsUser {
    internal class NativeHelpers {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO {
            public readonly UInt32 SessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;
            public readonly WTS_CONNECTSTATE_CLASS State;
        }
    }
    internal class NativeMethods {
        [DllImport("kernel32", SetLastError=true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hSnapshot);
        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, SafeHandle hToken, bool bInherit);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(SafeHandle hToken, String lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandle, uint dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref NativeHelpers.STARTUPINFO lpStartupInfo, out NativeHelpers.PROCESS_INFORMATION lpProcessInformation);
        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(SafeHandle ExistingTokenHandle, uint dwDesiredAccess, IntPtr lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out SafeNativeHandle DuplicateTokenHandle);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(SafeHandle TokenHandle, uint TokenInformationClass, SafeMemoryBuffer TokenInformation, int TokenInformationLength, out int ReturnLength);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);
        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);
        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("Wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(uint SessionId, out SafeNativeHandle phToken);
    }
    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid {
        public SafeMemoryBuffer(int cb) : base(true) {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }
        public SafeMemoryBuffer(IntPtr handle) : base(true) {
            base.SetHandle(handle);
        }
        protected override bool ReleaseHandle() {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }
    internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid {
        public SafeNativeHandle() : base(true) { }
        public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }
        protected override bool ReleaseHandle() {
            return NativeMethods.CloseHandle(handle);
        }
    }
    internal enum SECURITY_IMPERSONATION_LEVEL {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }
    internal enum SW {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_MAX = 10
    }
    internal enum TokenElevationType {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited,
    }
    internal enum TOKEN_TYPE {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }
    internal enum WTS_CONNECTSTATE_CLASS {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }
    public class Win32Exception : System.ComponentModel.Win32Exception {
        private string _msg;
        public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public Win32Exception(int errorCode, string message) : base(errorCode) {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }
        public override string Message { get { return _msg; } }
        public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
    }
    public class ProcessResult {
        public int ProcessId;
        public bool TimedOut;
    }
    public static class ProcessExtensions {
        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;
        private const int CREATE_NEW_CONSOLE = 0x00000010;
        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
        private static SafeNativeHandle GetSessionUserToken(bool elevated) {
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;
            if (NativeMethods.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount)) {
                try {
                    var arrayElementSize = Marshal.SizeOf(typeof(NativeHelpers.WTS_SESSION_INFO));
                    var current = pSessionInfo;
                    for (var i = 0; i < sessionCount; i++) {
                        var si = (NativeHelpers.WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(NativeHelpers.WTS_SESSION_INFO));
                        current = IntPtr.Add(current, arrayElementSize);
                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive) {
                            activeSessionId = si.SessionID;
                            break;
                        }
                    }
                }
                finally {
                    NativeMethods.WTSFreeMemory(pSessionInfo);
                }
            }
            if (activeSessionId == INVALID_SESSION_ID) {
                activeSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
            }
            SafeNativeHandle hImpersonationToken;
            if (!NativeMethods.WTSQueryUserToken(activeSessionId, out hImpersonationToken)) {
                throw new Win32Exception("WTSQueryUserToken failed to get access token.");
            }
            using (hImpersonationToken) {
                TokenElevationType elevationType = GetTokenElevationType(hImpersonationToken);
                if (elevationType == TokenElevationType.TokenElevationTypeLimited && elevated == true) {
                    using (var linkedToken = GetTokenLinkedToken(hImpersonationToken))
                        return DuplicateTokenAsPrimary(linkedToken);
                }
                else {
                    return DuplicateTokenAsPrimary(hImpersonationToken);
                }
            }
        }
        public static ProcessResult StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true, int wait = -1, bool elevated = true) {
            using (var hUserToken = GetSessionUserToken(elevated)) {
                var startInfo = new NativeHelpers.STARTUPINFO();
                startInfo.cb = Marshal.SizeOf(startInfo);
                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                IntPtr pEnv = IntPtr.Zero;
                if (!NativeMethods.CreateEnvironmentBlock(ref pEnv, hUserToken, false)) {
                    throw new Win32Exception("CreateEnvironmentBlock failed.");
                }
                try {
                    StringBuilder commandLine = new StringBuilder(cmdLine);
                    var procInfo = new NativeHelpers.PROCESS_INFORMATION();
                    if (!NativeMethods.CreateProcessAsUserW(hUserToken, appPath, commandLine, IntPtr.Zero, IntPtr.Zero, false, dwCreationFlags, pEnv, workDir, ref startInfo, out procInfo)) {
                        throw new Win32Exception("CreateProcessAsUser failed.");
                    }
                    try {
                        ProcessResult result = new ProcessResult();
                        result.ProcessId = procInfo.dwProcessId;
                        result.TimedOut = false;
                        uint waitResult = NativeMethods.WaitForSingleObject(procInfo.hProcess, (uint)wait);
                        if (waitResult == 0x00000102) {
                            NativeMethods.TerminateProcess(procInfo.hProcess, 999);
                            NativeMethods.WaitForSingleObject(procInfo.hProcess, 5000);
                            result.TimedOut = true;
                        }
                        return result;
                    }
                    finally {
                        NativeMethods.CloseHandle(procInfo.hThread);
                        NativeMethods.CloseHandle(procInfo.hProcess);
                    }
                }
                finally {
                    NativeMethods.DestroyEnvironmentBlock(pEnv);
                }
            }
        }
        private static SafeNativeHandle DuplicateTokenAsPrimary(SafeHandle hToken) {
            SafeNativeHandle pDupToken;
            if (!NativeMethods.DuplicateTokenEx(hToken, 0, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out pDupToken)) {
                throw new Win32Exception("DuplicateTokenEx failed.");
            }
            return pDupToken;
        }
        private static TokenElevationType GetTokenElevationType(SafeHandle hToken) {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 18)) {
                return (TokenElevationType)Marshal.ReadInt32(tokenInfo.DangerousGetHandle());
            }
        }
        private static SafeNativeHandle GetTokenLinkedToken(SafeHandle hToken) {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 19)) {
                return new SafeNativeHandle(Marshal.ReadIntPtr(tokenInfo.DangerousGetHandle()));
            }
        }
        private static SafeMemoryBuffer GetTokenInformation(SafeHandle hToken, uint infoClass) {
            int returnLength;
            bool res = NativeMethods.GetTokenInformation(hToken, infoClass, new SafeMemoryBuffer(IntPtr.Zero), 0, out returnLength);
            int errCode = Marshal.GetLastWin32Error();
            if (!res && errCode != 24 && errCode != 122) {
                throw new Win32Exception(errCode, String.Format("GetTokenInformation({0}) failed to get buffer length", infoClass));
            }
            SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(returnLength);
            if (!NativeMethods.GetTokenInformation(hToken, infoClass, tokenInfo, returnLength, out returnLength))
                throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass));
            return tokenInfo;
        }
    }
}
"@
}
function Serialize-Object {
    <#
    .SYNOPSIS
        Serializes PowerShell objects to JSON format with enhanced type handling.
    .DESCRIPTION
        Converts PowerShell objects to JSON strings with support for complex types
        including ScriptBlocks, nested hashtables, and circular reference detection.
        Works consistently across PowerShell 5.1 and PowerShell 7+.
    .PARAMETER Data
        The object to serialize. Accepts pipeline input.
    .PARAMETER Path
        Optional file path to save the serialized JSON. If not specified, returns the JSON string.
    .PARAMETER Depth
        Maximum depth for nested object serialization. Default is 20.
    .OUTPUTS
        System.String
        Returns the JSON string if Path is not specified.
    .EXAMPLE
        $data = @{ Name = "Test"; Value = 123 }
        $json = $data | Serialize-Object
        Serializes a hashtable to JSON string.
    .EXAMPLE
        $scriptBlock = { Get-Process }
        @{ Script = $scriptBlock } | Serialize-Object -Path "C:\Temp\data.json"
        Serializes an object containing a ScriptBlock to a file.
    .EXAMPLE
        $complexObject = [PSCustomObject]@{
            Users = @(
                @{ Name = "User1"; Groups = @("Admin", "Users") }
                @{ Name = "User2"; Groups = @("Users") }
            )
            Timestamp = Get-Date
        }
        $complexObject | Serialize-Object -Depth 10
        Serializes a complex nested object with specified depth.
    .NOTES
        ScriptBlocks are serialized as a special type marker for reconstruction during deserialization.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(ValueFromPipeline)][object]$Data,
        [Parameter()][string]$Path,
        [Parameter()][ValidateRange(1, 100)][int]$Depth = 20
    )
    begin {
        function ConvertTo-PlainObject {
            param(
                [object]$InputObject,
                [int]$CurrentDepth,
                [System.Collections.ArrayList]$ProcessedObjects
            )
            if ($null -eq $InputObject -or $CurrentDepth -ge $Depth) {
                return $null
            }
            if ($null -eq $ProcessedObjects) {
                $ProcessedObjects = [System.Collections.ArrayList]::new()
            }
            if ($InputObject -is [psobject] -and $null -ne $InputObject) {
                # Check for circular references
                foreach ($processed in $ProcessedObjects) {
                    if ([object]::ReferenceEquals($processed, $InputObject)) {
                        return "<<Circular Reference>>"
                    }
                }
                [void]$ProcessedObjects.Add($InputObject)
            }
            $actualType = $InputObject.GetType().Name
            $primitiveTypes = @('String', 'Int32', 'Int64', 'Double', 'Boolean', 'DateTime', 'Decimal', 'Single', 'Byte', 'SByte', 'Int16', 'UInt16', 'UInt32', 'UInt64', 'Char', 'Guid')
            if ($actualType -in $primitiveTypes) {
                return $InputObject
            }
            if ($InputObject -is [ScriptBlock]) {
                return @{
                    '_type'       = 'ScriptBlock'
                    'ScriptBlock' = $InputObject.ToString()
                }
            }
            if ($InputObject -is [PSCustomObject] -and $actualType -eq 'PSCustomObject') {
                $ht = @{}
                try {
                    $noteProperties = $InputObject | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue
                    foreach ($prop in $noteProperties) {
                        try {
                            $value = $InputObject.($prop.Name)
                            $ht[$prop.Name] = ConvertTo-PlainObject -InputObject $value -CurrentDepth ($CurrentDepth + 1) -ProcessedObjects $ProcessedObjects
                        }
                        catch {
                            Write-Verbose "Skipping property '$($prop.Name)': $($_.Exception.Message)"
                        }
                    }
                }
                catch {
                    Write-Verbose "Error processing PSCustomObject: $($_.Exception.Message)"
                }
                return $ht
            }
            if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.IDictionary]) {
                $ht = @{}
                try {
                    foreach ($key in $InputObject.Keys) {
                        $ht[$key] = ConvertTo-PlainObject -InputObject $InputObject[$key] -CurrentDepth ($CurrentDepth + 1) -ProcessedObjects $ProcessedObjects
                    }
                }
                catch {
                    Write-Verbose "Error processing hashtable: $($_.Exception.Message)"
                }
                return $ht
            }
            if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string] -and $InputObject -isnot [System.Collections.IDictionary]) {
                $collection = @()
                try {
                    foreach ($item in $InputObject) {
                        $collection += ConvertTo-PlainObject -InputObject $item -CurrentDepth ($CurrentDepth + 1) -ProcessedObjects $ProcessedObjects
                    }
                }
                catch {
                    Write-Verbose "Error processing collection: $($_.Exception.Message)"
                }
                return $collection
            }
            return $InputObject
        }
    }
    process {
        if ($null -eq $Data) {
            return $null
        }
        try {
            $plainObject = ConvertTo-PlainObject -InputObject $Data -CurrentDepth 0 -ProcessedObjects $null
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $jsonString = $plainObject | ConvertTo-Json -Depth $Depth -Compress -ErrorAction Stop
            }
            else {
                try {
                    $jsonString = $plainObject | ConvertTo-Json -Depth $Depth -Compress -ErrorAction Stop
                }
                catch {
                    Write-Verbose "ConvertTo-Json failed, using manual JSON serialization: $($_.Exception.Message)"
                    Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
                    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                    $serializer.MaxJsonLength = [int]::MaxValue
                    $serializer.RecursionLimit = $Depth
                    $jsonString = $serializer.Serialize($plainObject)
                }
            }
            if ($Path) {
                $directory = Split-Path -Path $Path -Parent
                if ($directory -and -not (Test-Path -Path $directory)) {
                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                }
                [System.IO.File]::WriteAllText($Path, $jsonString, [System.Text.Encoding]::UTF8)
                Write-Verbose "Serialized object to: $Path"
            }
            else {
                return $jsonString
            }
        }
        catch {
            throw "Serialization failed: $($_.Exception.Message)"
        }
    }
}
function Deserialize-Object {
    <#
    .SYNOPSIS
        Deserializes JSON data back to PowerShell objects with type reconstruction.
    .DESCRIPTION
        Converts JSON strings or files back to PowerShell objects, reconstructing
        special types like ScriptBlocks that were serialized with Serialize-Object.
        Works consistently across PowerShell 5.1 and PowerShell 7+.
    .PARAMETER Data
        JSON string to deserialize. Accepts pipeline input.
    .PARAMETER Path
        Path to a JSON file to deserialize.
    .OUTPUTS
        System.Object
        Returns the deserialized object (hashtable, array, or primitive type).
    .EXAMPLE
        $json = '{"Name":"Test","Value":123}'
        $object = $json | Deserialize-Object
        Deserializes a JSON string to a hashtable.
    .EXAMPLE
        $object = Deserialize-Object -Path "C:\Temp\data.json"
        Deserializes a JSON file to an object.
    .EXAMPLE
        $json = '{"_type":"ScriptBlock","ScriptBlock":"Get-Process"}'
        $result = $json | Deserialize-Object
        $result.ScriptBlock  # Returns an actual [ScriptBlock] object
        Deserializes JSON containing a ScriptBlock marker back to a ScriptBlock.
    .NOTES
        PSCustomObjects are converted to hashtables for easier manipulation.
        Int64 values within Int32 range are automatically converted to Int32.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(ValueFromPipeline)][object]$Data,
        [Parameter()][string]$Path
    )
    process {
        try {
            $jsonInput = if ($Path) {
                if (-not (Test-Path -Path $Path)) {
                    throw "File not found: $Path"
                }
                Get-Content -Path $Path -Raw -ErrorAction Stop
            }
            else {
                $Data
            }
            if ([string]::IsNullOrWhiteSpace($jsonInput)) {
                return $null
            }
            $deserializedObject = $null
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $deserializedObject = $jsonInput | ConvertFrom-Json -Depth 100 -ErrorAction Stop
            }
            else {
                try {
                    $deserializedObject = $jsonInput | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    Write-Verbose "ConvertFrom-Json failed, using JavaScriptSerializer: $($_.Exception.Message)"
                    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
                    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                    $serializer.MaxJsonLength = [int]::MaxValue
                    $serializer.RecursionLimit = 100
                    $deserializedObject = $serializer.DeserializeObject($jsonInput)
                }
            }
            function Reconstruct-Object {
                [CmdletBinding()]
                param(
                    [object]$InputObject
                )
                if ($null -eq $InputObject) {
                    return $null
                }
                if ($InputObject -is [PSCustomObject] -and $InputObject._type) {
                    # Handle special type markers
                    switch ($InputObject._type) {
                        'ScriptBlock' {
                            try {
                                return [ScriptBlock]::Create($InputObject.ScriptBlock)
                            }
                            catch {
                                Write-Verbose "Failed to recreate ScriptBlock: $($_.Exception.Message)"
                                return $InputObject.ScriptBlock
                            }
                        }
                        'Hashtable' {
                            $ht = @{}
                            if ($InputObject.Items -is [PSCustomObject] -or $InputObject.Items -is [System.Collections.IDictionary]) {
                                foreach ($prop in $InputObject.Items.PSObject.Properties) {
                                    $ht[$prop.Name] = Reconstruct-Object -InputObject $prop.Value
                                }
                            }
                            return $ht
                        }
                    }
                }
                if ($InputObject -is [System.Collections.IDictionary]) {
                    $newHashtable = @{}
                    foreach ($key in $InputObject.Keys) {
                        $newHashtable[$key] = Reconstruct-Object -InputObject $InputObject[$key]
                    }
                    return $newHashtable
                }
                $actualType = $InputObject.GetType().Name
                if (($InputObject -is [PSCustomObject] -and $actualType -ne 'Hashtable') -or $actualType -eq 'PSCustomObject') {
                    $ht = @{}
                    foreach ($prop in $InputObject.PSObject.Properties) {
                        $ht[$prop.Name] = Reconstruct-Object -InputObject $prop.Value
                    }
                    return $ht
                }
                if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string] -and $InputObject -isnot [System.Collections.IDictionary]) {
                    $newList = @()
                    foreach ($item in $InputObject) {
                        $newList += Reconstruct-Object -InputObject $item
                    }
                    return $newList
                }
                if ($InputObject -is [Int64]) {
                    # Convert Int64 to Int32 if within range
                    if ($InputObject -ge [Int32]::MinValue -and $InputObject -le [Int32]::MaxValue) {
                        return [Int32]$InputObject
                    }
                }
                return $InputObject
            }
            return Reconstruct-Object -InputObject $deserializedObject
        }
        catch {
            throw "Failed to deserialize JSON data. Error: $($_.Exception.Message)"
        }
    }
}
#endregion Helper Functions
#region Main Function
function Invoke-AsCurrentUser_WithArgs {
    <#
    .SYNOPSIS
        Executes a PowerShell scriptblock in the context of the currently logged-in user.
    .DESCRIPTION
        This function allows execution of PowerShell code as the interactive user session
        when running from a SYSTEM context. This is particularly useful for:
        - Intune/MEM deployments that need user-context operations
        - SCCM task sequences requiring user interaction
        - Scheduled tasks running as SYSTEM that need user access
        - Any SYSTEM-level process needing to perform user-specific operations
        The function creates a new PowerShell process in the user's session, executes
        the provided scriptblock, captures output via transcript, and returns results
        in a structured format.
    .PARAMETER ScriptBlock
        The PowerShell scriptblock to execute in the user's context. This is the code
        that will run as the logged-in user.
    .PARAMETER Argument
        A hashtable of variables to pass to the scriptblock. These will be available
        as variables within the scriptblock's scope.
    .PARAMETER TimeoutSeconds
        Maximum time in seconds to wait for script completion. Default is 60 seconds.
        After timeout, the process is terminated and an error is thrown.
    .PARAMETER ReturnTranscript
        When specified, returns the full result object including transcript data.
        Cannot be used with -NoWait.
    .PARAMETER ReturnPSCustomObject
        Returns the result as a PSCustomObject instead of just the Result property.
        Includes Status, ExecutionSuccess, Transcript, and ErrorMessage properties.
    .PARAMETER ReturnHashTable
        Returns the result as a hashtable instead of PSCustomObject.
    .PARAMETER NoWait
        Starts the process and returns immediately without waiting for completion.
        Returns the ProcessId for tracking. Cannot be used with -ReturnTranscript or -CaptureStreams.
    .PARAMETER UseWindowsPowerShell
        Forces execution in Windows PowerShell (powershell.exe) instead of the current
        PowerShell version. Useful for compatibility with PS 5.1-specific code.
    .PARAMETER NonElevatedSession
        Runs the process without elevation, even if the user has admin rights.
        By default, if the user has elevated privileges, the process runs elevated.
    .PARAMETER Visible
        Shows the PowerShell window during execution. By default, the window is hidden.
    .PARAMETER Quiet
        Suppresses status messages and logging output.
    .PARAMETER CaptureStreams
        Captures PowerShell output streams separately. The result object will include:
        - StdOut: Output stream (Write-Output, return values)
        - StdErr: Error stream (Write-Error)
        - Warnings: Warning stream (Write-Warning)
        - Verbose: Verbose stream (Write-Verbose)
        Note: Write-Host output goes to the Information stream and is captured in StdOut.
        Cannot be used with -NoWait.
    .PARAMETER WorkingDirectory
        Sets the working directory for the scriptblock execution.
        Defaults to the PowerShell executable's directory.
    .PARAMETER CleanTemp
        Removes the temporary directory after execution. Use with caution as this
        removes all files in the temp path used by this function.
    .OUTPUTS
        System.Object
        By default, returns the scriptblock's output.
        With -ReturnPSCustomObject or -ReturnHashTable, returns a structured result containing:
        - Result: The scriptblock's return value
        - Status: "Success" or "Failed"
        - ExecutionSuccess: Boolean indicating successful execution
        - Transcript: Parsed transcript object (with -ReturnTranscript)
        - ErrorMessage: Error details if execution failed
        - StdOut: Output stream content (with -CaptureStreams)
        - StdErr: Error stream content (with -CaptureStreams)
        - Warnings: Warning stream content (with -CaptureStreams)
        - Verbose: Verbose stream content (with -CaptureStreams)
        - ProcessId: The spawned process ID (with -NoWait)
    .EXAMPLE
        Invoke-AsCurrentUser_WithArgs -ScriptBlock { Get-Process | Select-Object -First 5 }
        Executes Get-Process as the current user and returns the first 5 processes.
    .EXAMPLE
        $result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
            [System.Environment]::GetFolderPath('Desktop')
        } -ReturnPSCustomObject
        $result.Result  # Returns the user's desktop path
        $result.Status  # "Success" or "Failed"
        Gets the logged-in user's desktop path with full result information.
    .EXAMPLE
        $params = @{
            AppName = "Microsoft Teams"
            Version = "1.5.0"
        }
        $scriptBlock = {
            Write-Output "Installing $AppName version $Version"
            # Installation logic here
        }
        Invoke-AsCurrentUser_WithArgs -ScriptBlock $scriptBlock -Argument $params
        Passes parameters to the scriptblock for use during execution.
    .EXAMPLE
        Invoke-AsCurrentUser_WithArgs -ScriptBlock {
            Start-Process "notepad.exe"
        } -Visible -NoWait
        Starts Notepad visible to the user without waiting for it to close.
    .EXAMPLE
        $result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
            $env:USERNAME
            $env:USERPROFILE
            Get-ChildItem $env:USERPROFILE\Desktop | Select-Object Name
        } -TimeoutSeconds 30 -UseWindowsPowerShell -ReturnTranscript
        Runs in Windows PowerShell 5.1 with a 30-second timeout and returns transcript.
    .EXAMPLE
        # Run a long operation with extended timeout
        $result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
            # Simulate long-running operation
            Start-Sleep -Seconds 120
            return "Completed"
        } -TimeoutSeconds 180 -Quiet
        Executes a long-running script with extended timeout and no status output.
    .EXAMPLE
        # Capture PowerShell streams separately
        $result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
            Write-Output "This goes to StdOut"
            Write-Error "This goes to StdErr"
            Write-Warning "This goes to Warnings"
            Write-Verbose "This goes to Verbose" -Verbose
            Write-Host "This also goes to StdOut"
        } -CaptureStreams -ReturnPSCustomObject
        $result.StdOut    # Contains output stream
        $result.StdErr    # Contains error stream
        $result.Warnings  # Contains warning stream
        $result.Verbose   # Contains verbose stream
        Captures all PowerShell output streams separately.
    .NOTES
        Requirements:
        - Must be running as SYSTEM or with SeDelegateSessionUserImpersonatePrivilege
        - A user must be logged in with an active session
        - Windows only (uses Windows-specific APIs)
        Limitations:
        - Cannot interact with UAC prompts
        - GUI operations require -Visible switch
        - Large data transfers may hit serialization limits
        Security Considerations:
        - Scripts run with the user's full permissions
        - Sensitive data in arguments is written to temp files briefly
        - Use -CleanTemp to ensure cleanup of temporary data
    .LINK
        https://github.com/Harze2k/Shared-PowerShell-Modules/Invoke-AsCurrentUser_WithArgs
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([object])]
    param (
        [Parameter(Mandatory, Position = 0)][ValidateNotNull()][scriptblock]$ScriptBlock,
        [Parameter()][switch]$ReturnTranscript,
        [Parameter()][switch]$NoWait,
        [Parameter()][switch]$UseWindowsPowerShell,
        [Parameter()][switch]$NonElevatedSession,
        [Parameter()][switch]$Visible,
        [Parameter()][switch]$ReturnPSCustomObject,
        [Parameter()][switch]$ReturnHashTable,
        [Parameter()][switch]$Quiet,
        [Parameter()][switch]$CaptureStreams,
        [Parameter()][ValidateNotNull()][hashtable]$Argument,
        [Parameter()][ValidateRange(1, 3600)][int]$TimeoutSeconds = 60,
        [Parameter()][ValidateScript({ $_ -eq $null -or $_ -eq '' -or (Test-Path -Path $_ -PathType Container) })][string]$WorkingDirectory = $null,
        [Parameter()][switch]$CleanTemp
    )
    #region Configuration Constants
    $script:INITIAL_RETRY_DELAY_MS = 100
    $script:RETRY_DELAY_MS = 250
    $script:POLL_INTERVAL_MS = 50
    $script:MAX_WAIT_BUFFER_SECONDS = 5
    $script:MAX_RETRIES = 3
    $script:PROCESS_KILL_TIMEOUT_MS = 2000
    $script:ERROR_PATTERN_REGEX = [regex]'failed|error'
    #endregion Configuration Constants
    #region Capture Original Invocation
    $scriptBlockPreview = $ScriptBlock.ToString().Trim() -replace '\s+', ' '
    if ($scriptBlockPreview.Length -gt 80) { $scriptBlockPreview = $scriptBlockPreview.Substring(0, 77) + '...' } # Truncate long scriptblocks for display
    $originalInvocation = @{
        ScriptBlockPreview = $scriptBlockPreview
        LineNumber         = $MyInvocation.ScriptLineNumber
        ScriptName         = if ($MyInvocation.ScriptName) { Split-Path $MyInvocation.ScriptName -Leaf } else { "Console" }
    }
    #endregion Capture Original Invocation
    #region Internal Functions
    function Test-SystemPrivileges {
        <#
        .SYNOPSIS
            Tests if the current process has sufficient privileges to run as another user.
        #>
        [CmdletBinding()]
        [OutputType([bool])]
        param()
        try {
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $isSystem = $currentIdentity.Name -eq 'NT AUTHORITY\SYSTEM'
            if (-not $isSystem) {
                $principal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
                $hasPrivilege = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $hasPrivilege) {
                    try {
                        $privileges = whoami /priv /fo csv 2>$null | ConvertFrom-Csv -ErrorAction Stop
                        $hasImpersonatePrivilege = $null -ne ($privileges | Where-Object {
                                $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' -and $_.State -eq "Enabled"
                            })
                        return $hasImpersonatePrivilege
                    }
                    catch {
                        return $false
                    }
                }
                return $hasPrivilege
            }
            return $isSystem
        }
        catch {
            Write-Warning "Could not determine privilege level: $($_.Exception.Message)"
            return $false
        }
    }
    function Get-SafeTempPath {
        <#
        .SYNOPSIS
            Gets or creates a safe temporary directory path for script execution.
        #>
        [CmdletBinding()]
        [OutputType([string])]
        param()
        $possiblePaths = @(
            #"$env:SystemDrive\Temp\Intune\Scripts\Winget\Logs\UserInvoke",
            "$env:SystemRoot\Temp\UserInvoke",
            "$env:ProgramData\UserInvoke\Temp"
        )
        foreach ($path in $possiblePaths) {
            try {
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
                $testFile = Join-Path $path "test_$(Get-Random).tmp"
                Set-Content -Path $testFile -Value "test" -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction Stop
                return $path
            }
            catch {
                Write-Error "Cannot use path $path : $($_.Exception.Message)"
                continue
            }
        }
        throw "Could not find or create a suitable temporary directory"
    }
    function ConvertFrom-PowerShellTranscript {
        <#
        .SYNOPSIS
            Parses a PowerShell transcript file into a structured object.
        #>
        [CmdletBinding()]
        [OutputType([PSCustomObject])]
        param (
            [Parameter(Mandatory, ValueFromPipeline)][ValidateNotNullOrEmpty()][string]$TranscriptPath
        )
        process {
            if (-not (Test-Path -Path $TranscriptPath)) {
                Write-Error "Transcript file not found: $TranscriptPath"
                return
            }
            $transcriptData = @{
                StartTime         = $null
                Username          = $null
                RunAsUser         = $null
                MachineName       = $null
                OSVersion         = $null
                HostApplication   = $null
                ProcessId         = $null
                PowerShellVersion = $null
                TranscriptPath    = $TranscriptPath
                TranscriptContent = ""
            }
            $transcriptContent = [System.Collections.Generic.List[string]]::new(100)
            $isHeader = $false
            $headerParsed = $false
            $reader = $null
            try {
                $reader = [System.IO.File]::OpenText($TranscriptPath)
                while ($null -ne ($line = $reader.ReadLine())) {
                    $line = $line.Trim()
                    if ($line -eq '**********************') {
                        if (-not $isHeader) {
                            $isHeader = $true
                        }
                        else {
                            $isHeader = $false
                            $headerParsed = $true
                        }
                        continue
                    }
                    if ($isHeader) {
                        switch -Regex ($line) {
                            '^Start time:\s+(\d{14})$' {
                                try {
                                    $transcriptData.StartTime = [DateTime]::ParseExact($matches[1], "yyyyMMddHHmmss", $null)
                                }
                                catch {
                                    Write-Warning "Unable to parse Start Time: $($_.Exception.Message)"
                                }
                            }
                            '^Username:\s+(.+)$' {
                                $transcriptData.Username = $matches[1].Trim()
                            }
                            '^RunAs User:\s+(.+)$' {
                                $transcriptData.RunAsUser = $matches[1].Trim()
                            }
                            '^Machine:\s+(.+?)\s+\(([^)]+)\)$' {
                                $transcriptData.MachineName = $matches[1].Trim()
                                $transcriptData.OSVersion = $matches[2].Trim()
                            }
                            '^Host Application:\s+(.+)$' {
                                $hostAppLine = $matches[1].Trim()
                                if ($hostAppLine -match '^"?([^"\s]+)"?') {
                                    $transcriptData.HostApplication = $matches[1]
                                }
                                else {
                                    $transcriptData.HostApplication = $hostAppLine
                                }
                            }
                            '^Process ID:\s+(\d+)$' {
                                $transcriptData.ProcessId = [int]$matches[1]
                            }
                            '^PSVersion:\s+(.+)$' {
                                $transcriptData.PowerShellVersion = $matches[1].Trim()
                            }
                        }
                    }
                    elseif ($headerParsed -and $line -notmatch '^Transcript started, output file is') {
                        $transcriptContent.Add($line)
                    }
                }
            }
            catch {
                Write-Error "Error reading transcript file: $($_.Exception.Message)"
                return
            }
            finally {
                if ($reader) {
                    $reader.Dispose()
                }
            }
            $transcriptData.TranscriptContent = $transcriptContent -join "`n"
            $missingFields = @()
            foreach ($key in $transcriptData.Keys) {
                if ($key -ne 'TranscriptContent' -and $key -ne 'TranscriptPath' -and $null -eq $transcriptData[$key]) {
                    $missingFields += $key
                }
            }
            if ($missingFields.Count -gt 0) {
                Write-Warning "The following fields were not found or could not be parsed: $($missingFields -join ', ')"
            }
            return [PSCustomObject]$transcriptData
        }
    }
    function Invoke-InternalAsCurrentUser {
        <#
        .SYNOPSIS
            Internal implementation that handles the actual process creation and execution.
        #>
        [CmdletBinding()]
        param(
            [string]$TempPath,
            [string]$SerializedData,
            [int]$TimeoutSeconds,
            [string]$WorkingDirectory,
            [hashtable]$OriginalInvocation,
            [bool]$IsQuiet,
            [bool]$IsCaptureStreams
        )
        if (-not ('RunAsUser.ProcessExtensions' -as [type])) {
            # Load C# type if not already loaded
            try {
                Add-Type -TypeDefinition (Get-RunAsUserCSharpSource) -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Message -notmatch "already exists") {
                    throw $_
                }
            }
        }
        $SerializeObjectDef = ${function:Serialize-Object}.ToString()
        $DeserializeObjectDef = ${function:Deserialize-Object}.ToString()
        $streamCaptureSetup = if ($IsCaptureStreams) {
            @'
$global:CapturedOutput = [System.Collections.Generic.List[string]]::new()
$global:CapturedErrors = [System.Collections.Generic.List[string]]::new()
$global:CapturedWarnings = [System.Collections.Generic.List[string]]::new()
$global:CapturedVerbose = [System.Collections.Generic.List[string]]::new()
'@
        }
        else { "" }
        $streamCaptureCleanup = if ($IsCaptureStreams) {
            @'
$stdOutContent = $global:CapturedOutput -join "`n"
$stdErrContent = $global:CapturedErrors -join "`n"
$warningContent = $global:CapturedWarnings -join "`n"
$verboseContent = $global:CapturedVerbose -join "`n"
'@
        }
        else {
            @'
$stdOutContent = $null
$stdErrContent = $null
$warningContent = $null
$verboseContent = $null
'@
        }
        #region Build Wrapped Script
        $wrappedScriptBuilder = [System.Text.StringBuilder]::new(8192)
        [void]$wrappedScriptBuilder.AppendLine("Try { Stop-Transcript -ErrorAction SilentlyContinue } Catch { `$error.Clear() }")
        [void]$wrappedScriptBuilder.AppendLine("Start-Transcript -Path `"$TempPath\Invoke-AsCurrentUser_WithArgs.log`" -Force")
        [void]$wrappedScriptBuilder.AppendLine("function Serialize-Object {")
        [void]$wrappedScriptBuilder.AppendLine("    $SerializeObjectDef")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("function Deserialize-Object {")
        [void]$wrappedScriptBuilder.AppendLine("    $DeserializeObjectDef")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine($streamCaptureSetup)
        [void]$wrappedScriptBuilder.AppendLine("`$scriptData = `$null")
        [void]$wrappedScriptBuilder.AppendLine("`$rawData = @'")
        [void]$wrappedScriptBuilder.AppendLine($SerializedData)
        [void]$wrappedScriptBuilder.AppendLine("'@")
        [void]$wrappedScriptBuilder.AppendLine("try {")
        [void]$wrappedScriptBuilder.AppendLine("    `$scriptData = `$rawData | Deserialize-Object")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("catch {")
        [void]$wrappedScriptBuilder.AppendLine("    if (`$PSVersionTable.PSVersion.Major -eq 5) {")
        [void]$wrappedScriptBuilder.AppendLine("        try {")
        [void]$wrappedScriptBuilder.AppendLine("            `$scriptData = `$rawData | ConvertFrom-Json")
        [void]$wrappedScriptBuilder.AppendLine("        }")
        [void]$wrappedScriptBuilder.AppendLine("        catch {")
        [void]$wrappedScriptBuilder.AppendLine("            Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue")
        [void]$wrappedScriptBuilder.AppendLine("            `$serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer")
        [void]$wrappedScriptBuilder.AppendLine("            `$serializer.MaxJsonLength = [int]::MaxValue")
        [void]$wrappedScriptBuilder.AppendLine("            `$scriptData = `$serializer.DeserializeObject(`$rawData)")
        [void]$wrappedScriptBuilder.AppendLine("        }")
        [void]$wrappedScriptBuilder.AppendLine("    }")
        [void]$wrappedScriptBuilder.AppendLine("    else { throw }")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("`$variables = `$scriptData.Argument")
        [void]$wrappedScriptBuilder.AppendLine("if(`$scriptData.ScriptBlock) {")
        [void]$wrappedScriptBuilder.AppendLine("    `$scriptBlock = [ScriptBlock]::Create(`$scriptData.ScriptBlock)")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("else {")
        [void]$wrappedScriptBuilder.AppendLine("    `$scriptBlock = [ScriptBlock]::Create(`$scriptData)")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("if (`$variables -ne `$null) {")
        [void]$wrappedScriptBuilder.AppendLine("    if (`$variables -is [hashtable]) {")
        [void]$wrappedScriptBuilder.AppendLine("        foreach (`$item in `$variables.GetEnumerator()) {")
        [void]$wrappedScriptBuilder.AppendLine("            New-Variable -Name `$item.Key -Value `$item.Value -Force")
        [void]$wrappedScriptBuilder.AppendLine("            if (`$PSVersionTable.PSVersion.Major -eq 5) {")
        [void]$wrappedScriptBuilder.AppendLine("                Set-Variable -Name `$item.Key -Value `$item.Value -Scope Global -Force")
        [void]$wrappedScriptBuilder.AppendLine("            }")
        [void]$wrappedScriptBuilder.AppendLine("        }")
        [void]$wrappedScriptBuilder.AppendLine("    }")
        [void]$wrappedScriptBuilder.AppendLine("    else {")
        [void]$wrappedScriptBuilder.AppendLine("        foreach (`$prop in `$variables.PSObject.Properties) {")
        [void]$wrappedScriptBuilder.AppendLine("            New-Variable -Name `$prop.Name -Value `$prop.Value -Force")
        [void]$wrappedScriptBuilder.AppendLine("            if (`$PSVersionTable.PSVersion.Major -eq 5) {")
        [void]$wrappedScriptBuilder.AppendLine("                Set-Variable -Name `$prop.Name -Value `$prop.Value -Scope Global -Force")
        [void]$wrappedScriptBuilder.AppendLine("            }")
        [void]$wrappedScriptBuilder.AppendLine("        }")
        [void]$wrappedScriptBuilder.AppendLine("    }")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("`$result = `$null")
        [void]$wrappedScriptBuilder.AppendLine("`$executionSuccess = `$false")
        [void]$wrappedScriptBuilder.AppendLine("`$errorMessage = `$null")
        [void]$wrappedScriptBuilder.AppendLine("try {")
        [void]$wrappedScriptBuilder.AppendLine("    `$error.Clear()")
        if ($IsCaptureStreams) {
            [void]$wrappedScriptBuilder.AppendLine("    `$allOutput = & `$scriptBlock 2>&1 3>&1 4>&1 5>&1")
            [void]$wrappedScriptBuilder.AppendLine("    foreach (`$item in `$allOutput) {")
            [void]$wrappedScriptBuilder.AppendLine("        if (`$item -is [System.Management.Automation.ErrorRecord]) {")
            [void]$wrappedScriptBuilder.AppendLine("            `$global:CapturedErrors.Add(`$item.ToString())")
            [void]$wrappedScriptBuilder.AppendLine("        }")
            [void]$wrappedScriptBuilder.AppendLine("        elseif (`$item -is [System.Management.Automation.WarningRecord]) {")
            [void]$wrappedScriptBuilder.AppendLine("            `$global:CapturedWarnings.Add(`$item.Message)")
            [void]$wrappedScriptBuilder.AppendLine("        }")
            [void]$wrappedScriptBuilder.AppendLine("        elseif (`$item -is [System.Management.Automation.VerboseRecord]) {")
            [void]$wrappedScriptBuilder.AppendLine("            `$global:CapturedVerbose.Add(`$item.Message)")
            [void]$wrappedScriptBuilder.AppendLine("        }")
            [void]$wrappedScriptBuilder.AppendLine("        elseif (`$item -is [System.Management.Automation.InformationRecord]) {")
            [void]$wrappedScriptBuilder.AppendLine("            `$global:CapturedOutput.Add(`$item.MessageData.ToString())")
            [void]$wrappedScriptBuilder.AppendLine("        }")
            [void]$wrappedScriptBuilder.AppendLine("        else {")
            [void]$wrappedScriptBuilder.AppendLine("            `$global:CapturedOutput.Add(`$item.ToString())")
            [void]$wrappedScriptBuilder.AppendLine("        }")
            [void]$wrappedScriptBuilder.AppendLine("    }")
            [void]$wrappedScriptBuilder.AppendLine("    `$result = `$global:CapturedOutput -join `"``n`"")
        }
        else {
            [void]$wrappedScriptBuilder.AppendLine("    `$result = & `$scriptBlock")
        }
        [void]$wrappedScriptBuilder.AppendLine("    `$executionSuccess = `$true")
        [void]$wrappedScriptBuilder.AppendLine("    if (`$Error.Count -gt 0) {")
        [void]$wrappedScriptBuilder.AppendLine("        `$errorString = `"Script completed with non-terminating errors: `$(`$Error -join '; ')`"")
        [void]$wrappedScriptBuilder.AppendLine("        Write-Warning `$errorString")
        [void]$wrappedScriptBuilder.AppendLine("    }")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("catch {")
        [void]$wrappedScriptBuilder.AppendLine("    `$errorMessage = `"The ScriptBlock failed. Error: `$(`$_.Exception.Message)`"")
        [void]$wrappedScriptBuilder.AppendLine("    `$result = `$errorMessage")
        [void]$wrappedScriptBuilder.AppendLine("    `$executionSuccess = `$false")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine($streamCaptureCleanup)
        [void]$wrappedScriptBuilder.AppendLine("Try { Stop-Transcript -ErrorAction SilentlyContinue } Catch { `$error.Clear() }")
        [void]$wrappedScriptBuilder.AppendLine("`$transcriptContent = try {")
        [void]$wrappedScriptBuilder.AppendLine("    Get-Content `"$TempPath\Invoke-AsCurrentUser_WithArgs.log`" -Raw -ErrorAction Stop")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("catch {")
        [void]$wrappedScriptBuilder.AppendLine("    `"Transcript file could not be read: `$(`$_.Exception.Message)`"")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("`$resultData = @{")
        [void]$wrappedScriptBuilder.AppendLine("    Result = `$result")
        [void]$wrappedScriptBuilder.AppendLine("    Transcript = `$transcriptContent")
        [void]$wrappedScriptBuilder.AppendLine("    ExecutionSuccess = `$executionSuccess")
        [void]$wrappedScriptBuilder.AppendLine("    ErrorMessage = `$errorMessage")
        if ($IsCaptureStreams) {
            [void]$wrappedScriptBuilder.AppendLine("    StdOut = `$stdOutContent")
            [void]$wrappedScriptBuilder.AppendLine("    StdErr = `$stdErrContent")
            [void]$wrappedScriptBuilder.AppendLine("    Warnings = `$warningContent")
            [void]$wrappedScriptBuilder.AppendLine("    Verbose = `$verboseContent")
        }
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("try {")
        [void]$wrappedScriptBuilder.AppendLine("    if (`$PSVersionTable.PSVersion.Major -eq 5) {")
        [void]$wrappedScriptBuilder.AppendLine("        `$resultData | ConvertTo-Json -Depth 5 | Out-File `"$TempPath\result.json`" -Encoding UTF8 -Force")
        [void]$wrappedScriptBuilder.AppendLine("    }")
        [void]$wrappedScriptBuilder.AppendLine("    else {")
        [void]$wrappedScriptBuilder.AppendLine("        `$resultData | Serialize-Object -Path `"$TempPath\result.json`" -Depth 5")
        [void]$wrappedScriptBuilder.AppendLine("    }")
        [void]$wrappedScriptBuilder.AppendLine("    [System.IO.File]::WriteAllText(`"$TempPath\result.json.complete`", `"done`")")
        [void]$wrappedScriptBuilder.AppendLine("}")
        [void]$wrappedScriptBuilder.AppendLine("catch {")
        [void]$wrappedScriptBuilder.AppendLine("    `"{'Result':'Error','ExecutionSuccess':false,'ErrorMessage':'Serialization failed'}`" | Out-File `"$TempPath\result.json`" -Encoding UTF8 -Force")
        [void]$wrappedScriptBuilder.AppendLine("    [System.IO.File]::WriteAllText(`"$TempPath\result.json.complete`", `"done`")")
        [void]$wrappedScriptBuilder.AppendLine("}")
        $wrappedScript = $wrappedScriptBuilder.ToString()
        #endregion Build Wrapped Script
        #region Execute Process
        try {
            $pwshPath = if ($UseWindowsPowerShell) {
                "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe"
            }
            else {
                (Get-Process -Id $PID).Path
            }
            if (-not (Test-Path $pwshPath)) {
                throw "PowerShell executable not found at: $pwshPath"
            }
            $pwshCommand = ""
            $scriptPath = $null
            if ($UseWindowsPowerShell) {
                $scriptPath = Join-Path $env:TEMP "$([guid]::NewGuid()).ps1"
                Set-Content -Path $scriptPath -Value $wrappedScript -Encoding UTF8 -Force
                $pwshCommand = "-NOP -ExecutionPolicy Bypass -File `"$scriptPath`""
            }
            else {
                $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($wrappedScript))
                $maxLength = 32767
                if ($encodedCommand.Length -gt $maxLength) {
                    $scriptPath = Join-Path $env:TEMP "$([guid]::NewGuid()).ps1"
                    Set-Content -Path $scriptPath -Value $wrappedScript -Encoding UTF8 -Force
                    $pwshCommand = "-NOP -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
                }
                else {
                    $pwshCommand = "-NOP -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encodedCommand"
                }
            }
            $workDir = if ($WorkingDirectory) { $WorkingDirectory } else { Split-Path $pwshPath -Parent }
            $resultPath = "$TempPath\result.json"
            $completeMarkerPath = "$resultPath.complete"
            if (Test-Path $resultPath) { Remove-Item $resultPath -Force -ErrorAction SilentlyContinue }
            if (Test-Path $completeMarkerPath) { Remove-Item $completeMarkerPath -Force -ErrorAction SilentlyContinue }
            $timeoutMs = if ($NoWait) { 1 } else { $TimeoutSeconds * 1000 }
            $result = [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
                $pwshPath,
                "`"$pwshPath`" $pwshCommand",
                $workDir,
                $Visible.IsPresent,
                $timeoutMs,
                !$NonElevatedSession
            )
            $processId = $result.ProcessId
            Write-Verbose "Started process with ID: $processId"
            if ($NoWait) {
                return [pscustomobject]@{
                    Result           = "Process Queued/Started with ID $processId"
                    Transcript       = $null
                    Status           = "Success"
                    ExecutionSuccess = $true
                    ProcessId        = $processId
                }
            }
            if ($result.TimedOut) {
                throw "Timeout waiting for script execution after $TimeoutSeconds seconds"
            }
            #region Wait for Completion
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            $maxWaitTime = $TimeoutSeconds + $script:MAX_WAIT_BUFFER_SECONDS
            $pollInterval = $script:POLL_INTERVAL_MS
            while (-not (Test-Path $completeMarkerPath)) {
                Start-Sleep -Milliseconds $pollInterval
                if ($pollInterval -lt $script:RETRY_DELAY_MS) {
                    $pollInterval += 25
                }
                if ($timer.Elapsed.TotalSeconds -gt $maxWaitTime) {
                    $processHandle = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    if ($processHandle -and -not $processHandle.HasExited) {
                        Write-Warning "Process $processId still running after timeout. Terminating..."
                        try {
                            $processHandle.Kill()
                            $processHandle.WaitForExit($script:PROCESS_KILL_TIMEOUT_MS)
                        }
                        catch {
                            Write-Verbose "Could not kill process: $($_.Exception.Message)"
                        }
                    }
                    throw "Timeout waiting for script execution after $TimeoutSeconds seconds"
                }
            }
            #endregion Wait for Completion
            if (-not (Test-Path $resultPath)) {
                throw "Completion marker found but result.json is missing"
            }
            #region Parse Results
            try {
                $transcript = ConvertFrom-PowerShellTranscript -TranscriptPath "$TempPath\Invoke-AsCurrentUser_WithArgs.log"
                $retryCount = 0
                $resultData = $null
                $retryDelay = $script:INITIAL_RETRY_DELAY_MS
                while ($retryCount -lt $script:MAX_RETRIES) {
                    try {
                        $resultData = Deserialize-Object -Path $resultPath
                        break
                    }
                    catch {
                        $retryCount++
                        if ($retryCount -ge $script:MAX_RETRIES) {
                            throw "Failed to parse execution results after $($script:MAX_RETRIES) attempts: $($_.Exception.Message)"
                        }
                        Write-Verbose "Retry $retryCount : JSON parse failed, retrying..."
                        Start-Sleep -Milliseconds $retryDelay
                        $retryDelay *= 2
                    }
                }
                $random = Get-Random # Backup logs
                Copy-Item -Path "$TempPath\Invoke-AsCurrentUser_WithArgs.log" -Destination "$TempPath\Invoke-AsCurrentUser_WithArgs_Old_$random.log" -ErrorAction SilentlyContinue
                Copy-Item -Path $resultPath -Destination "$TempPath\Invoke-AsCurrentUser_WithArgs_Old_$random.json" -ErrorAction SilentlyContinue
            }
            catch {
                throw "Failed to parse execution results: $($_.Exception.Message)"
            }
            #endregion Parse Results
            #region Determine Status
            $Status = "Failed"
            if ($resultData) {
                if ($resultData['ExecutionSuccess']) {
                    $Status = if ($resultData.ExecutionSuccess -eq $true) { "Success" } else { "Failed" }
                    if ($Status -eq "Failed" -and $resultData.ErrorMessage) {
                        Write-Verbose "Execution failed with error: $($resultData.ErrorMessage)"
                    }
                }
                else {
                    $isErrorString = $resultData.Result -is [string] -and $script:ERROR_PATTERN_REGEX.IsMatch($resultData.Result)
                    $Status = if ($isErrorString) { "Failed" } else { "Success" }
                }
            }
            #endregion Determine Status
            #region Output Status
            if (-not $IsQuiet) {
                $scriptPreview = $OriginalInvocation.ScriptBlockPreview
                $lineNumber = $OriginalInvocation.LineNumber
                $scriptName = $OriginalInvocation.ScriptName
                $locationInfo = "Line: $lineNumber"
                if ($scriptName -ne "Console") {
                    $locationInfo += " in $scriptName"
                }
                $message = "Executed: { $scriptPreview } - Status: $Status ($locationInfo)"
                $color = if ($Status -eq "Success") { "Green" } else { "Red" }
                if (Get-Command New-Log -ErrorAction SilentlyContinue) {
                    if ($Status -eq 'Failed') {
                        New-Log $message -Level WARNING
                    }
                    else {
                        New-Log $message -Level SUCCESS
                    }
                }
                else {
                    Write-Host $message -ForegroundColor $color
                }
            }
            #endregion Output Status
            #region Cleanup
            $filesToCleanup = @($resultPath)
            if (Test-Path $completeMarkerPath) { $filesToCleanup += $completeMarkerPath }
            if ($scriptPath -and (Test-Path $scriptPath)) { $filesToCleanup += $scriptPath }
            if (Test-Path -Path "$TempPath\Invoke-AsCurrentUser_WithArgs.log") { $filesToCleanup += "$TempPath\Invoke-AsCurrentUser_WithArgs.log" }
            if ($filesToCleanup.Count -gt 0) {
                Remove-Item -Path $filesToCleanup -Force -ErrorAction SilentlyContinue
            }
            #endregion Cleanup
            #region Build Result Object
            $resultObject = @{
                Result     = $resultData.Result
                Transcript = $transcript
                Status     = $Status
            }
            if ($resultData['ExecutionSuccess']) {
                $resultObject.ExecutionSuccess = $resultData.ExecutionSuccess
            }
            if ($resultData['ErrorMessage'] -and $resultData.ErrorMessage) {
                $resultObject.ErrorMessage = $resultData.ErrorMessage
            }
            if ($IsCaptureStreams) {
                if ($resultData['StdOut']) { $resultObject.StdOut = $resultData.StdOut }
                if ($resultData['StdErr']) { $resultObject.StdErr = $resultData.StdErr }
                if ($resultData['Warnings']) { $resultObject.Warnings = $resultData.Warnings }
                if ($resultData['Verbose']) { $resultObject.Verbose = $resultData.Verbose }
            }
            return [pscustomobject]$resultObject
            #endregion Build Result Object
        }
        catch {
            if ($scriptPath -and (Test-Path $scriptPath)) {
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            }
            if ($_.Exception.Message -match "Timeout") {
                throw
            }
            $errorResult = @{
                Result     = $null
                Transcript = $null
                Status     = "Failed"
                Error      = $_.Exception.Message
            }
            if ($ReturnPSCustomObject.IsPresent) {
                return [pscustomobject]$errorResult
            }
            else {
                return $errorResult
            }
        }
        #endregion Execute Process
    }
    #endregion Internal Functions
    #region Parameter Validation
    if ($ReturnTranscript -and $NoWait) {
        Write-Warning "Cannot return transcript when NoWait is specified"
        return
    }
    if ($CaptureStreams -and $NoWait) {
        Write-Warning "Cannot capture streams when NoWait is specified"
        return
    }
    #endregion Parameter Validation
    #region Privilege Check
    if (-not (Test-SystemPrivileges)) {
        Write-Warning "Insufficient privileges. You must run this script as SYSTEM or with SeDelegateSessionUserImpersonatePrivilege."
        return
    }
    #endregion Privilege Check
    #region Main Execution
    try {
        $tempPath = Get-SafeTempPath
        $scriptData = @{
            ScriptBlock = $ScriptBlock.ToString()
        }
        if ($Argument -and $Argument.Count -gt 0) {
            $scriptData.Argument = $Argument
        }
        $serializedData = Serialize-Object -Data $scriptData
        $result = Invoke-InternalAsCurrentUser `
            -TempPath $tempPath `
            -SerializedData $serializedData `
            -TimeoutSeconds $TimeoutSeconds `
            -WorkingDirectory $WorkingDirectory `
            -OriginalInvocation $originalInvocation `
            -IsQuiet $Quiet.IsPresent `
            -IsCaptureStreams $CaptureStreams.IsPresent `
            -Verbose:$VerbosePreference
        if ($null -eq $result) {
            return
        }
        if ($NoWait) {
            return $result
        }
        if ($ReturnPSCustomObject.IsPresent -or $ReturnHashTable.IsPresent -or $ReturnTranscript.IsPresent) {
            if ($ReturnHashTable.IsPresent -and $result -is [pscustomobject]) {
                $hashResult = @{}
                $result.psobject.properties | ForEach-Object {
                    $hashResult[$_.Name] = $_.Value
                }
                return $hashResult
            }
            return $result
        }
        if ($result.Status -eq 'Success') {
            return $result.Result
        }
        else {
            if (-not $Quiet) {
                Write-Error "The remote script execution failed. See the output for details."
            }
            return $result.Result
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "Timeout") {
            throw $_
        }
        Write-Error "Failed to execute script as current user: $errorMsg"
        return "Failed to execute script as current user: $errorMsg"
    }
    finally {
        if ($CleanTemp.IsPresent -and $tempPath -and (Test-Path $tempPath)) {
            try {
                Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Could not clean up temporary directory: $tempPath"
            }
        }
    }
    #endregion Main Execution
}
#endregion Main Function
#region Module Exports
Export-ModuleMember -Function @(
    'Invoke-AsCurrentUser_WithArgs',
    'Serialize-Object',
    'Deserialize-Object',
    'Get-RunAsUserCSharpSource'
)
#endregion Module Exports