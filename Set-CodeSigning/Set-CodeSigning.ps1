<#
.SYNOPSIS
	Sign PowerShell scripts with a Code Signing certificate

.DESCRIPTION
    This scripts permits to sign PowerShell scripts with a Code Signing certificate. It needs to be
    on the same directory level of the scripts to sign / folders where are the scripts to sign

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





# SIG # Begin signature block
# MIIMtgYJKoZIhvcNAQcCoIIMpzCCDKMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0sRqmlEqU5j5sxxaVau9DB8Q
# FbSgggoPMIIDpzCCAo+gAwIBAgIQcV6XFZlN2ZZLRKdprbnVPTANBgkqhkiG9w0B
# AQsFADBZMRMwEQYKCZImiZPyLGQBGRYDb3JnMRwwGgYKCZImiZPyLGQBGRYMZmVp
# Zy1lY29saW50MSQwIgYDVQQDExtmZWlnLWVjb2xpbnQtTEZBLURPTS1TMDAtQ0Ew
# IBcNMTcwMTA2MDgxODQwWhgPMjExNjAxMDYwODI4NDBaMFkxEzARBgoJkiaJk/Is
# ZAEZFgNvcmcxHDAaBgoJkiaJk/IsZAEZFgxmZWlnLWVjb2xpbnQxJDAiBgNVBAMT
# G2ZlaWctZWNvbGludC1MRkEtRE9NLVMwMC1DQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBANXg8fneOVfRSq0vkxYK88MfL/5UJpS9XLIvVyo6PGgDYiw1
# Oyu52rmDLK//sAhMbsymGiNHy7QpAcZoCqy2GNWgBKNUgTBNpA02a1h0LL89kpZ8
# 4GcSaTLUVzYn7mq6NcGIje6dBbnVcC740A3QRxbDBBp2Ip8CwajQsoSh/6El91Ce
# DPdL8n1gN/BE90w3pyyt6kJ5XA5cO5JGOjp28Lyym1M2eFRPGb0OlMftqMAXCzAQ
# sMdny1EuQQS6AY8bR4pt8sWebkwKYI4soxPQggkZ962P+dQhPbCsc0l1hIjvLl8n
# RDGyuTy9uZGzvWQPgxYTQmw1d1AC8kGviX9dE8ECAwEAAaNpMGcwEwYJKwYBBAGC
# NxQCBAYeBABDAEEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFDNswEYssj4GPNInsLDvVhQmISEiMBAGCSsGAQQBgjcVAQQDAgEAMA0G
# CSqGSIb3DQEBCwUAA4IBAQBQpPBpsk+YLmr/jBhtWimn+d7tvtkbJhgiLFdwE+qi
# 5SpQPjCthpCA8rJdiuuWUBdIJOcpshQj7BiVYKzHjfmSVv0HW0JaCkuJFDjzIGQm
# wKDoPnDRsIwW7hEJhr5Vx5opTi5BokvLhuj0TWtZCAacJ27X3Bqs5kkYbjcWb7Vk
# tEqgPQO8xlad7/vcgU9/I0/xXarxheTxAI2HugI3SmE06AUaxrQKZEQgNpUybat3
# DJ7fBNx7EzmHfM8ZYBwDZVY4PrhoASURnrQfZHCZvIistsA9S8LC4OmKWU5pZGRu
# iXnqSSFusoNE5k86oPouMup8TFIwFEVQpzqk6ku5qYzrMIIGYDCCBUigAwIBAgIT
# NgAACPLpdjoadBfBCAAAAAAI8jANBgkqhkiG9w0BAQsFADBZMRMwEQYKCZImiZPy
# LGQBGRYDb3JnMRwwGgYKCZImiZPyLGQBGRYMZmVpZy1lY29saW50MSQwIgYDVQQD
# ExtmZWlnLWVjb2xpbnQtTEZBLURPTS1TMDAtQ0EwHhcNMjEwMzIzMTQxMTIxWhcN
# MjIwMzIzMTQxMTIxWjCBvDETMBEGCgmSJomT8ixkARkWA29yZzEcMBoGCgmSJomT
# 8ixkARkWDGZlaWctZWNvbGludDEOMAwGA1UECxMFU0lURVMxDDAKBgNVBAsTA0xH
# QjEOMAwGA1UECxMFVXNlcnMxDzANBgNVBAsTBkNhbXB1czEOMAwGA1UECxMFU3Rh
# ZmYxDDAKBgNVBAsTA0lDVDERMA8GA1UECxMISm9uYXRoYW4xFzAVBgNVBAMTDk1P
# VUNPIEpvbmF0aGFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsR2Q
# jL9gFOsDtCnQ1Sp37RMWQ6mJYtms5uAcEaAeCy3WVeX9RIn/BcfE13yPW+ls9F6s
# qkjuPkmKWEwdeVvMSiMWtqNn3Fd3Lhh+iZ8wl4supkR3cN3EupLtNkC9fumsUIte
# wWb5Amysr54eOVmj76hf6pHyOKSJ1h5Ln33zkFG7eu3lIjdODKEYMv4d017SjWT/
# XSaDnpEOFbd+zKvEXa8nxRCCR7OAUjO/Yfg0MPZdxG/dANBxCx9HLtG+DsfsRvcZ
# 6wsvYXrMJXb09ZctS84oEPDqQIaVzjS0dzOTEMENRKhENNS9lNW0CWwGRPOcgWFT
# lUwfVjtoMljr5aRooQIDAQABo4ICuzCCArcwPQYJKwYBBAGCNxUHBDAwLgYmKwYB
# BAGCNxUIgonmTYaOyF+BwZkngcGbHoOuyGwshbaYDoejjXUCAWQCAQMwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMBsGCSsGAQQBgjcVCgQOMAww
# CgYIKwYBBQUHAwMwHQYDVR0OBBYEFKP2MsuafHcaJnTcFR7N4EYTmeSrMB8GA1Ud
# IwQYMBaAFDNswEYssj4GPNInsLDvVhQmISEiMIHiBgNVHR8EgdowgdcwgdSggdGg
# gc6GgctsZGFwOi8vL0NOPWZlaWctZWNvbGludC1MRkEtRE9NLVMwMC1DQSxDTj1M
# RkEtRE9NLVMwMCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
# U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1mZWlnLWVjb2xpbnQsREM9b3Jn
# P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxE
# aXN0cmlidXRpb25Qb2ludDCB0gYIKwYBBQUHAQEEgcUwgcIwgb8GCCsGAQUFBzAC
# hoGybGRhcDovLy9DTj1mZWlnLWVjb2xpbnQtTEZBLURPTS1TMDAtQ0EsQ049QUlB
# LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
# Z3VyYXRpb24sREM9ZmVpZy1lY29saW50LERDPW9yZz9jQUNlcnRpZmljYXRlP2Jh
# c2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA6BgNVHREEMzAx
# oC8GCisGAQQBgjcUAgOgIQwfSm9uYXRoYW4uTW91Y29AZmVpZy1lY29saW50Lm9y
# ZzANBgkqhkiG9w0BAQsFAAOCAQEAEj6kfPav1L6xCVqytS8jYimvmIaKXbU/a6fa
# Hxy8nTOOfqaYNTK4eInLEDxs5xKJGPxkvNzclkNfpb3xgKfI7shiqLgjPSnOOuw/
# IY03Y5pJw7ShFnoafEc0lGJgfPE9cle5PGL8KyQklRZQL7bhd/oW35OnRzvgEfVd
# /nXsELEkus5iPlC6VsBcvfM6LuuLqXeReSm2napFhww/l6q8eAMl+K4sTJdiRA4Y
# +5DhrpvhRu+7U8/wjDxaF2daINHXNWvs1L1XQUQSn4xz70yCs3z4Aq8gDaR384wo
# sDgcY5Eo4csCsLGXQZ8uyp9/CCbc7CKkcfzVoHOYtaCODJ7HKzGCAhEwggINAgEB
# MHAwWTETMBEGCgmSJomT8ixkARkWA29yZzEcMBoGCgmSJomT8ixkARkWDGZlaWct
# ZWNvbGludDEkMCIGA1UEAxMbZmVpZy1lY29saW50LUxGQS1ET00tUzAwLUNBAhM2
# AAAI8ul2Ohp0F8EIAAAAAAjyMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRC4DhapfSlftlMSvd1
# lQk7yyfrCjANBgkqhkiG9w0BAQEFAASCAQCofF7DF+IzQnzGssNXH8DnQPWh8FR0
# +/CzE3HOYZF7RPna5TZzPulIPGeeK0VSPktvY0jV0abICO6p4a1kUwrLeV+MvWHX
# k72HgpotrRH8yX/Syz2YaE5uLNZhDqR5+BBAb8pZyY+5MyWrd995bu+F/mbfw9A1
# RqBQpABe2KnssRBkR7m/j3N+k94gq6iaufgZ8zG34YWylP/yI2/HXqPykjfLWalF
# nZGp8DMcGnSdwuoYRCYcDG/TxRX9lsyamzsDNjR4iLsTA+bNCIwMC8i153AxQMlj
# suEFy4cXGMqwfJTDAlVxTuopHsYVwrX9GKWozuMtLjTdW3bKA0J+B45f
# SIG # End signature block
