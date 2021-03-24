<#
.SYNOPSIS
	Sign PowerShell scripts with a Code Signing certificate

.DESCRIPTION
    This scripts permits to sign PowerShell scripts with a Code Signing certificate. It needs to be
    on the same directory level of the scripts to sign / folders where are the scripts to sign. A log
    file will be created on the same folder as this script.

    To sign this script you can use the following command :
    Set-AuthenticodeSignature -FilePath 'PATH_TO_THIS_SCRIPT' -Certificate (Get-ChildItem -Path 'cert:CurrentUser\My\' -CodeSigningCert) -IncludeChain All -TimestampServer 'http://timestamp.fabrikam.com/scripts/timstamper.dll'

.PARAMETER Auto
    Set the script to look for .ps1 scripts on all folders where this script is

.PARAMETER Manual
    Override the Auto mode. Set the script to look for .ps1 scripts on folder that is set on Folder parameter

.PARAMETER Folder
    The folder name that is on the same level of this script where to look for scripts to sign

.EXAMPLE
    # Start the script in Auto mode. Will check every .ps1 files to sign on every folder recursively that are on the same level of this script
    .\Set-CodeSigning.ps1

.EXAMPLE
    # Start the script in Manual mode. Will check every .ps1 to sign on specified folder recursively that is on the same level of this script
    .\Set-CodeSigning.ps1 -Manual -Folder 'ScriptsToSign'

.NOTES
    FileName : Set-CodeSigning.ps1
	Author   : Jonathan Mouco
    Contact  : @Wavee7
    Created  : 21.11.13
    Updated  : 24.03.21

	Contributors :

    Thanks : The work of @NickolajA (Nickolaj Andersen) and @MoDaly_IT (Maurice Daly) helped me to do a better script

    Version history :
    1.0.0 - (2013-11-21) - Script created
    2.0.0 - (2021-03-24) - The script as been rebuilded from scratch adding parameter sets and other functions
#>


#----------------------------------------#
# ---  -    General Information   -  --- #
#----------------------------------------#

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Auto')]

param (
    [Parameter(Mandatory = $false, ParameterSetName = 'Auto', HelpMessage = 'Set the script to sign all Install.ps1 scripts on same parent folders.')]
	[Switch]$Auto,

    [Parameter(Mandatory = $false, ParameterSetName = 'Manual', HelpMessage = 'Set the script to sign all Install.ps1 scripts on specific folders.')]
	[Switch]$Manual,

    [Parameter(Mandatory = $true, ParameterSetName = 'Manual', HelpMessage = 'Define the folder name where the scripts to Sign will be.')]
	[String]$Folder = ''
)

Begin
{
    [String]$scriptRoot = $PSScriptRoot
    [String]$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

    [System.Object]$scriptsToSign = @()
}
Process
{
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # *** -                               Function                               - *** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    function Write-CMLogEntry {
		param(
			[Parameter(Mandatory = $true, HelpMessage = 'Message added to the log file.')]
			[ValidateNotNullOrEmpty()]
			[String]$Message,
			
			[Parameter(Mandatory = $true, HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
			[ValidateNotNullOrEmpty()]
			[ValidateSet('1', '2', '3')]
			[String]$Severity,

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
		if (-not(Test-Path -Path 'variable:global:TimezoneBias'))
        {
			[String]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
			if ($TimezoneBias -match '^-')
            {
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
		try
        {
			Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $logFilePath -ErrorAction Stop
		}
		catch [System.Exception]
        {
			Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
		}
	}

    Write-CMLogEntry -Message 'Start of execution' -Severity 1


    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # * -                             Validation Steps                             - * #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    # Certificate validation
    $codeSignCert = Get-ChildItem -Path 'cert:CurrentUser\My\' -CodeSigningCert

    if (-not([System.String]::IsNullOrEmpty($codeSignCert)))
    {
        if ($codeSignCert.Verify())
        {
            Write-CMLogEntry -Message "A Code Signing certificate was found and is valid - Thumbprint : $($codeSignCert.Thumbprint)" -Severity 1
        }
        else
        {
            Write-CMLogEntry -Message 'A Code Signing certificate was found but is not valid' -Severity 2
            Write-CMLogEntry -Message 'End of execution' -Severity 1; exit
        }
    }
    else
    {
        Write-CMLogEntry -Message 'There is no Code Signing certificate available' -Severity 2
        Write-CMLogEntry -Message 'End of execution' -Severity 1; exit
    }

    # Determine the scripts to sign
    if ($PSCmdLet.ParameterSetName -like 'Auto')
    {
        Write-CMLogEntry -Message 'Running mode : Auto' -Severity 1

        # Get the scripts to sign
        $scriptsToSign = Get-ChildItem -Path $scriptRoot -Filter 'Install.ps1' -File -Recurse
    }
    elseif ($PSCmdLet.ParameterSetName -like 'Manual')
    {
        Write-CMLogEntry -Message 'Running mode : Manual' -Severity 1

        [String]$scriptsToSignPath = Join-Path -Path $scriptRoot -ChildPath $Folder

        if (Test-Path -Path $scriptsToSignPath)
        {
            Write-CMLogEntry -Message "'$scriptsToSignPath' is a valid path" -Severity 1

            # Get the scripts to sign
            $scriptsToSign = Get-ChildItem -Path $scriptsToSignPath -Filter 'Install.ps1' -File -Recurse
        }
        else
        {
            Write-CMLogEntry -Message "$scriptsToSignPath is not a valid path" -Severity 2
            Write-CMLogEntry -Message 'End of execution' -Severity 1; exit
        }
    }

    # Determine if there are scripts to sign
    if (-not([System.String]::IsNullOrEmpty($scriptsToSign)))
    {
        Write-CMLogEntry -Message "Found $($scriptsToSign.Count) scripts" -Severity 1
    }
    else
    {
        Write-CMLogEntry -Message 'There is no scripts found' -Severity 2
        Write-CMLogEntry -Message 'End of execution' -Severity 1; exit
    }

    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # * -                                   MAIN                                   - * #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    foreach ($script in $scriptsToSign)
    {
        try
        {
            if ((Get-AuthenticodeSignature -FilePath $script.FullName | Select-Object -Property Status).Status -ne 'Valid')
            {
                Write-CMLogEntry -Message "Attempt to sign '$script' on '$($script.DirectoryName)'" -Severity 1
                Set-AuthenticodeSignature -FilePath $script.Fullname -Certificate $codeSignCert -IncludeChain All -TimestampServer 'http://timestamp.fabrikam.com/scripts/timstamper.dll' | Out-Null
                Write-CMLogEntry -Message 'Success' -Severity 1
            }
            else
            {
                Write-CMLogEntry -Message "The '$($script.Name)' on '$($script.DirectoryName)' already have a valid signature" -Severity 1
            }
        }
        catch
        {
            Write-CMLogEntry -Message "An error occured while trying to sign $($script.Name) on $($script.PSParentPath). Error message: $($_.Exception.Message)" -Severity 3
        }
    }
}
End
{
    Write-CMLogEntry -Message 'End of execution' -Severity 1

    exit 0
}





