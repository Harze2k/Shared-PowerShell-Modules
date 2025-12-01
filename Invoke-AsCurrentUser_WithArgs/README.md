# Invoke-AsCurrentUser_WithArgs

A PowerShell module for executing scripts in the context of the currently logged-in user from a SYSTEM context.

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/Invoke-AsCurrentUser_WithArgs)](https://www.powershellgallery.com/packages/Invoke-AsCurrentUser_WithArgs)
[![Module Downloads](https://img.shields.io/powershellgallery/dt/Invoke-AsCurrentUser_WithArgs)](https://www.powershellgallery.com/packages/Invoke-AsCurrentUser_WithArgs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Harze2k/Shared-PowerShell-Modules/blob/main/LICENSE)

## Overview

This module provides functionality to execute PowerShell scriptblocks as the currently logged-in user when running from a SYSTEM context. This is essential for:

- **Intune/MEM deployments** that need user-context operations
- **SCCM task sequences** requiring user interaction or access
- **Scheduled tasks** running as SYSTEM that need user-specific operations
- **Any SYSTEM-level process** needing to perform uAser-specific operations

## Features

- ✅ Execute scriptblocks as the interactive user session
- ✅ Pass arguments/variables to the remote scriptblock
- ✅ Capture transcript output and execution results
- ✅ Support for both Windows PowerShell 5.1 and PowerShell 7+
- ✅ Configurable timeout handling
- ✅ Optional stream capture (stdout/stderr)
- ✅ Elevated or non-elevated execution options
- ✅ Visible or hidden window execution

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Running as SYSTEM or with `SeDelegateSessionUserImpersonatePrivilege`
- A user must be logged in with an active session

## Installation

### From PowerShell Gallery (Recommended)

```powershell
Install-Module -Name Invoke-AsCurrentUser_WithArgs -Scope CurrentUser
```

### Manual Installation

1. Download the latest release
2. Extract to a PowerShell module path:
   - User: `$HOME\Documents\PowerShell\Modules\Invoke-AsCurrentUser_WithArgs\`
   - System: `C:\Program Files\PowerShell\Modules\Invoke-AsCurrentUser_WithArgs\`
3. Import the module:

```powershell
Import-Module Invoke-AsCurrentUser_WithArgs
```

## Quick Start

### Basic Usage

```powershell
# Simple command execution
Invoke-AsCurrentUser_WithArgs -ScriptBlock { Get-Process | Select-Object -First 5 }
```

### Passing Arguments

```powershell
$params = @{
    AppName = "Microsoft Teams"
    Version = "1.5.0"
}
$scriptBlock = {
    Write-Output "Installing $AppName version $Version"
}
Invoke-AsCurrentUser_WithArgs -ScriptBlock $scriptBlock -Argument $params
```

### Getting Full Result Information

```powershell
$result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    [System.Environment]::GetFolderPath('Desktop')
} -ReturnPSCustomObject

$result.Result  # The actual output
$result.Status  # "Success" or "Failed"
$result.ExecutionSuccess  # Boolean
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `ScriptBlock` | ScriptBlock | **Required.** The PowerShell code to execute as the user |
| `Argument` | Hashtable | Variables to pass to the scriptblock |
| `TimeoutSeconds` | Int | Maximum wait time (default: 60, max: 3600) |
| `ReturnTranscript` | Switch | Include full transcript in result |
| `ReturnPSCustomObject` | Switch | Return structured result object |
| `ReturnHashTable` | Switch | Return result as hashtable |
| `NoWait` | Switch | Start process and return immediately |
| `UseWindowsPowerShell` | Switch | Force Windows PowerShell 5.1 |
| `NonElevatedSession` | Switch | Run without elevation |
| `Visible` | Switch | Show the PowerShell window |
| `Quiet` | Switch | Suppress status messages |
| `CaptureStreams` | Switch | Capture PowerShell streams (StdOut, StdErr, Warnings, Verbose) separately |
| `WorkingDirectory` | String | Set the working directory |
| `CleanTemp` | Switch | Remove temp files after execution |

## Examples

### Get User's Desktop Path

```powershell
$desktopPath = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    [System.Environment]::GetFolderPath('Desktop')
}
Write-Host "User's desktop is at: $desktopPath"
```

### Install Application with User Notification

```powershell
Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "Installation complete!",
        "Setup",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
} -Visible
```

### Get User Registry Values

```powershell
$userSettings = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    @{
        Theme = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize').AppsUseLightTheme
        WallpaperPath = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').WallPaper
    }
} -ReturnPSCustomObject

Write-Host "User theme setting: $($userSettings.Result.Theme)"
```

### Run with Timeout and Error Handling

```powershell
try {
    $result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
        # Long running operation
        Start-Sleep -Seconds 30
        return "Completed successfully"
    } -TimeoutSeconds 45 -ReturnPSCustomObject
    if ($result.Status -eq 'Success') {
        Write-Host "Operation completed: $($result.Result)"
    }
    else {
        Write-Warning "Operation failed: $($result.ErrorMessage)"
    }
}
catch {
    Write-Error "Timeout or critical error: $($_.Exception.Message)"
}
```

### Start Process Without Waiting

```powershell
$result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    Start-Process "notepad.exe"
} -NoWait -Visible

Write-Host "Started process with ID: $($result.ProcessId)"
```

### Capture Output Streams

```powershell
$result = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    Write-Output "Standard output message"
    Write-Error "Error output message"
    Write-Warning "Warning message"
    Write-Verbose "Verbose message" -Verbose
    Write-Host "Host output (goes to StdOut)"
} -CaptureStreams -ReturnPSCustomObject

Write-Host "StdOut: $($result.StdOut)"
Write-Host "StdErr: $($result.StdErr)"
Write-Host "Warnings: $($result.Warnings)"
Write-Host "Verbose: $($result.Verbose)"
```

### Use in Intune Win32 App

```powershell
# Detection script running as SYSTEM
$userAppData = Invoke-AsCurrentUser_WithArgs -ScriptBlock {
    $env:LOCALAPPDATA
}

$appPath = Join-Path $userAppData "YourApp\app.exe"
if (Test-Path $appPath) {
    Write-Host "Application detected"
    exit 0
}
else {
    exit 1
}
```

## Return Object Structure

When using `-ReturnPSCustomObject`, the result contains:

```powershell
[PSCustomObject]@{
    Result           = <ScriptBlock output>
    Status           = "Success" | "Failed"
    ExecutionSuccess = $true | $false
    Transcript       = [PSCustomObject]@{
        StartTime         = [DateTime]
        Username          = [String]
        RunAsUser         = [String]
        MachineName       = [String]
        OSVersion         = [String]
        HostApplication   = [String]
        ProcessId         = [Int]
        PowerShellVersion = [String]
        TranscriptContent = [String]
    }
    ErrorMessage     = [String]  # Only if failed
    StdOut           = [String]  # Only with -CaptureStreams (Output stream)
    StdErr           = [String]  # Only with -CaptureStreams (Error stream)
    Warnings         = [String]  # Only with -CaptureStreams (Warning stream)
    Verbose          = [String]  # Only with -CaptureStreams (Verbose stream)
    ProcessId        = [Int]     # Only with -NoWait
}
```

## Helper Functions

The module also exports these utility functions:

### Serialize-Object

Serializes PowerShell objects to JSON with enhanced type handling:

```powershell
$data = @{ Name = "Test"; Script = { Get-Process } }
$json = $data | Serialize-Object
# or
Serialize-Object -Data $data -Path "C:\Temp\data.json"
```

### Deserialize-Object

Deserializes JSON back to PowerShell objects:

```powershell
$object = $json | Deserialize-Object
# or
$object = Deserialize-Object -Path "C:\Temp\data.json"
```

## Troubleshooting

### "Insufficient privileges" Error

Ensure you're running as SYSTEM or have the `SeDelegateSessionUserImpersonatePrivilege`. In Intune, deploy as "System" context.

### "No active user session" Error

A user must be logged in interactively. This won't work on servers without logged-in users or before user login.

### Timeout Issues

- Increase `-TimeoutSeconds` for long-running operations
- Use `-NoWait` for fire-and-forget scenarios
- Check if the script is waiting for user input (use `-Visible` to debug)

### Serialization Errors

- Large objects may hit serialization limits
- Complex types may not serialize properly - use simpler return types
- ScriptBlocks are serialized as strings and recreated

## Security Considerations

- Scripts run with the user's full permissions
- Sensitive data in arguments is written to temp files briefly
- Use `-CleanTemp` to ensure cleanup of temporary data
- The function cannot bypass UAC prompts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the original RunAsUser module: https://github.com/KelvinTegelaar/RunAsUser
- Thanks to the PowerShell community for feedback and contributions