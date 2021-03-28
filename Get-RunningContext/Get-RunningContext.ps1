<#
.SYNOPSIS
    Get the current Windows running context

.DESCRIPTION
    This function will tell if we are running in WinPE or FullOS

.EXAMPLE
    # Get the current Windows running context of the script
    .\Get-RunningContext

.NOTES
    FileName : Get-RunningContext.ps1
    Author   : Jonathan Mouco
    Contact  : @Wavee7

    Version history :
    1.0.0 - (2021-03-28) - Script created
#>
function Get-RunningContext {
    <#
        .SYNOPSIS
            Get the current Windows running context

        .OUTPUTS
            Return a String with the current running context
            ('FullOS', 'WinPE')
    #>

    [CmdletBinding()]

    [OutputType([String])]

    [String]$locStrCurrentContext = 'FullOS'


    if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -like '*SYSTEM') {
        try {
            # Create an object to access the task sequence environment
            $tsEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment' -ErrorAction Stop

            # Check if we are running on WinPE
            if ($tsEnv.Value('_SMSTSInWinPE') -eq $true) {
                $locStrCurrentContext = 'WinPE'
            }
        }
        catch [System.Exception] {
            Write-Warning -Message 'Unable to construct Microsoft.SMS.TSEnvironment object'
        }
    }

    Write-Output -InputObject $locStrCurrentContext
}