@{
    # Script module file associated with this manifest
    RootModule           = 'Invoke-AsCurrentUser_WithArgs.psm1'
    # Version number
    ModuleVersion        = '1.0.0'
    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')
    # ID used to uniquely identify this module
    GUID                 = 'f7a3b2c1-8d4e-4f6a-9b5c-1e2d3f4a5b6c'
    # Author
    Author               = 'Harze2k'
    # Company or vendor
    CompanyName          = 'Community'
    # Copyright statement
    Copyright            = '(c) 2025. All rights reserved.'
    # Description
    Description          = 'Execute PowerShell scriptblocks in the context of the currently logged-in user from a SYSTEM context. Ideal for Intune deployments, SCCM task sequences, and scheduled tasks.'
    # Minimum PowerShell version required
    PowerShellVersion    = '5.1'
    # Functions to export from this module
    FunctionsToExport    = @(
        'Invoke-AsCurrentUser_WithArgs',
        'Serialize-Object',
        'Deserialize-Object',
        'Get-RunAsUserCSharpSource'
    )
    # Cmdlets to export
    CmdletsToExport      = @()
    # Variables to export
    VariablesToExport    = @()
    # Aliases to export
    AliasesToExport      = @()
    # Private data to pass to the module
    PrivateData          = @{
        PSData = @{
            # Tags applied to this module for module discovery
            Tags                       = @('RunAsUser', 'Intune', 'SCCM', 'SYSTEM', 'UserContext', 'Deployment', 'Windows')
            # License URI
            LicenseUri                 = 'https://github.com/Harze2k/Shared-PowerShell-Modules/Invoke-AsCurrentUser_WithArgs/LICENSE'
            # Project URI
            ProjectUri                 = 'https://github.com/Harze2k/Shared-PowerShell-Modules/Invoke-AsCurrentUser_WithArgs'
            # Icon URI
            # IconUri = ''
            # Release notes
            ReleaseNotes               = @'
## Version 1.0.0
- Initial release
- Execute scriptblocks as currently logged-in user
- Pass arguments/variables to scriptblocks
- Capture transcript and execution results
- Support for PowerShell 5.1 and 7+
- Configurable timeout handling
- Optional stream capture (stdout/stderr)
'@
            # Prerelease string
            # Prerelease = ''
            # Flag to indicate whether the module requires explicit user acceptance for install/update
            RequireLicenseAcceptance   = $false
            # External dependent modules
            ExternalModuleDependencies = @()
        }
    }
    # Help info URI
    HelpInfoURI          = 'https://github.com/Harze2k/Shared-PowerShell-Modules/Invoke-AsCurrentUser_WithArgs/wiki'
}
