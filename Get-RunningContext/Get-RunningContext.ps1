<#
.SYNOPSIS
    Get the current Windows running context on SMS and MDT

.DESCRIPTION
    This function will tell if we are running in FullOS, FullOS_OSD_SMS, FullOS_OSD_MDT or WinPE context

.EXAMPLE
    # Get the current Windows running context of the script
    .\Get-RunningContext

.NOTES
    FileName : Get-RunningContext.ps1
    Author   : Jonathan Mouco
    Contact  : @Wavee7

    Version history :
    1.0.2 - (2021-04-21) - Added MDT detection and changed the output result to reflect if it's SMS or MDT
    1.0.1 - (2021-04-02) - Added FullOS_OSD so we can detect that we are on FullOS within the OSD
    1.0.0 - (2021-03-28) - Script created
#>
function Get-RunningContext {
    <#
    .SYNOPSIS
        Get the current Windows running context

    .OUTPUTS
        Return a String with the current running context
        ('FullOS', 'FullOS_OSD_SMS', 'FullOS_OSD_MDT', 'WinPE')
    #>

    [CmdletBinding()]

    [OutputType([String])]

    [String]$locStrCurrentContext = 'FullOS'


    if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -like '*SYSTEM') {
        try {
            # Create an object to access the task sequence environment
            [System.MarshalByRefObject]$locSMBROTSEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment' -ErrorAction Stop

            # Check if we are running on WinPE or FullOS
            if ($locSMBROTSEnv.Value('_SMSTSInWinPE') -eq $true) {
                $locStrCurrentContext = 'WinPE'
            }
            else {
                $locStrCurrentContext = 'FullOS_OSD_SMS'
            }
        }
        catch [System.Exception] {
            if (Test-Path -Path 'C:\MININT') {
                $locStrCurrentContext = 'FullOS_OSD_MDT'
            }
        }
    }

    Write-Output -InputObject $locStrCurrentContext
}