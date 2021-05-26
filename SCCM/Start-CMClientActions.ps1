<#
.SYNOPSIS
    Run actions of SCCM Agent

.DESCRIPTION
    This scripts permits to run actions of SCCM Agent on local or remote machines.
    It is possible to run 'ALL' actions or to run specific ones. Only a set of
    possible actions are on this script but it is possible to add more.

.PARAMETER Targets
    Optional. Set targets to apply the SCCM actions (Default: 'localhost')

.PARAMETER Actions
    Optional. Set the SCCM actions to apply to the targets (Default: 'ALL')

.EXAMPLE
    # Start the script with the default values (Targets : 'localhost'; Actions : 'ALL')
    .\Start-CMClientActions.ps1

.EXAMPLE
    # Start the script with some targets and default actions ('ALL')
    .\Start-CMClientActions.ps1 -Targets 'Client1', 'Client2'

.EXAMPLE
    # Start the script with some targets and some actions
    .\Start-CMClientActions.ps1 -Targets 'Client1', 'Client2' -Actions ApplicationDeployment, MachinePolicy

.NOTES
    FileName : Start-CMClientActions.ps1
    Author   : Jonathan Mouco
    Contact  : @Wavee7

    Version history :
    1.0.0 - (2021-05-26) - Script created
#>


#----------------------------------------#
# ---  -    General Information   -  --- #
#----------------------------------------#

[CmdletBinding(SupportsShouldProcess = $true)]

param (
    [Parameter(Mandatory = $false, HelpMessage = 'Name of the target computers')]
    [String[]]$Targets = @('localhost'),

    [Parameter(Mandatory = $false, HelpMessage = 'Name of actions tu run')]
    [ValidateSet('ApplicationDeployment', 'DiscoveryData', 'FileCollection', 'HardwareInventory', 'MachinePolicy', 'SoftwareInventory', 'WindowsInstallerSourceList')]
    [String[]]$Actions = @('All')
)

Begin {
    [System.Object]$objScriptInfo = [PSCustomObject]@{
        RunningContext  = ''
        LogPath         = ''
        LogFileName     = ''
        ScriptRoot      = $null
    }

    # Set location
    Set-Location -Path $PSScriptRoot; $objScriptInfo.ScriptRoot = Get-Item -Path (Get-Location).Path
    [String]$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
}
Process {
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # *** -                               Function                               - *** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    function Get-LogPath {
        <#
        .SYNOPSIS
            The Get-LogPath determine the path of the log file

        .PARAMETER InitInfo
            General informations about the script
            name

        .OUTPUTS
            Path to log folder
        #>

        [CmdletBinding()]

        [OutputType([String])]

        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$InitInfo
        )


        switch -wildcard ($InitInfo.RunningContext) {
            'FullOS' {
                if ($InitInfo.ScriptRoot.FullName -like '*\ccmcache\*') {
                    # Return log path
                    Write-Output -InputObject "$env:windir\CCM\Logs"
                }
                else {
                    # Return log path
                    Write-Output -InputObject $InitInfo.ScriptRoot.FullName
                }

                break
            }

            'FullOS_OSD_SMS' {
                # Create an object to access the task sequence environment
                $tsEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment'

                # Return log path
                Write-Output -InputObject $tsEnv.Value('_SMSTSLogPath')

                break
            }

            'FullOS_OSD_MDT' {
                # Return log path
                Write-Output -InputObject 'C:\MININT\SMSOSD\OSDLogs'

                break
            }
        }
    }

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

    function Start-CMClientActions {

        [CmdletBinding()]

        param (
            [Parameter(Mandatory = $false)]
            [String[]]$Targets = @('localhost'),

            [Parameter(Mandatory = $false)]
            [String[]]$Actions = @('All')
        )

        [Hashtable]$locAvailableActions = @{
            'ApplicationDeployment'         = '{00000000-0000-0000-0000-000000000121}';
            'DiscoveryData'                 = '{00000000-0000-0000-0000-000000000003}';
            'FileCollection'                = '{00000000-0000-0000-0000-000000000010}';
            'HardwareInventory'             = '{00000000-0000-0000-0000-000000000001}';
            'MachinePolicy'                 = '{00000000-0000-0000-0000-000000000021}';
            'SoftwareInventory'             = '{00000000-0000-0000-0000-000000000002}';
            'WindowsInstallerSourceList'    = '{00000000-0000-0000-0000-000000000032}'
        }

        [Boolean]$locCanRunAction = $false


        foreach ($target in $Targets) {
            "Current target : $target" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName

            # Check the availability of the target
            if ($target -ne 'localhost') {
                if (Test-Connection -ComputerName $target -Count 1 -Quiet) {
                    "$target is online" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName
                    $locCanRunAction = $true
                }
                else {
                    $locCanRunAction = $false
                    "$target does not seems to be online" | Write-CMLogEntry -Severity '2' -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName
                }
            }
            else {
                $locCanRunAction = $true
            }

            # Run actions if allowed
            if ($locCanRunAction) {
                foreach ($action in $Actions) {
                    try {
                        if ($action -eq 'All') {
                            $locAvailableActions.GetEnumerator() | ForEach-Object {
                                "Current action to trigger : $($_.Key) (GUID: $($_.Value))" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName
                                Invoke-WMIMethod -ComputerName $target -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule $($_.Value) | Out-Null
                            }
                        }
                        else {
                            $scheduleGUID = $locAvailableActions[$action]
                            "Current action to trigger : $action (GUID: $scheduleGUID)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName
                            Invoke-WMIMethod -ComputerName $target -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule $scheduleGUID | Out-Null
                        }
                    }
                    catch {
                        Write-CMLogEntry -Message $_.Exception.Message -Severity 1
                    }
                }
            }
        }
    }

    function Write-CMLogEntry {
        <#
        .SYNOPSIS
            The Write-CMLogEntry function permits to write to a log file readable by CMTrace

        .PARAMETER Message
            Message to add to the log file

        .PARAMETER Severity
            Severity of the message
            1: Information
            2: Warning
            3: Error

        .PARAMETER LogsDirectory
            Path to the log directory. By default it will be the script root path

        .PARAMETER FileName
            Log file name. By default it will be the name of this script

        .INPUTS
            String

        .OUTPUTS
            None
        #>

        param(
            [Parameter(Mandatory = $true, ValueFromPipeline, HelpMessage = 'Message added to the log file.')]
            [ValidateNotNullOrEmpty()]
            [String]$Message,
            
            [Parameter(Mandatory = $false, HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('1', '2', '3')]
            [String]$Severity = '1',

            [Parameter(Mandatory = $false, HelpMessage = 'Name of the log directory location.')]
            [ValidateNotNullOrEmpty()]
            [String]$LogsDirectory = $scriptRoot,

            [Parameter(Mandatory = $false, HelpMessage = 'Name of the log file that the entry will written to.')]
            [ValidateNotNullOrEmpty()]
            [String]$FileName = "$scriptName.log"
        )


        # Determine log file location
        $logFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName

        # Construct time stamp for log entry
        if (-not(Test-Path -Path 'variable:global:TimezoneBias')) {
            [String]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
            if ($TimezoneBias -match '^-') {
                $TimezoneBias = $TimezoneBias.Replace('-', '+')
            }
            else {
                $TimezoneBias = '-' + $TimezoneBias
            }
        }

        $Time = -join @((Get-Date -Format 'HH:mm:ss.fff'), $TimezoneBias)

        # Construct date for log entry
        $Date = (Get-Date -Format 'MM-dd-yyyy')

        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        # Construct final log entry
        $LogText = "<![LOG[$($Message)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$FileName"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $logFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }



    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # * -                                   MAIN                                   - * #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    # Determine the current Running Context
    $objScriptInfo.RunningContext = Get-RunningContext

    # Determine the log directory and stuff
    $objScriptInfo.LogPath = Get-LogPath -InitInfo $objScriptInfo
    $objScriptInfo.LogFileName = "$scriptName.log"

    # Write to log
    "[START] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName
    "Running Context : $($objScriptInfo.RunningContext)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName

    Start-CMClientActions -Targets $Targets -Actions $Actions
}
End {
    "[END] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName

    exit 0
}