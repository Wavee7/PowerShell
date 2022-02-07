#requires -modules 'ActiveDirectory'

<#
.SYNOPSIS
    New-ADPasswordExpiresNotification notify AD users when their password are going to expire or has expired

.DESCRIPTION
    New-ADPasswordExpiresNotification notify AD users when their password are going to expire or has expired.
    It also permits to create an AD password state report and a live report.

.EXAMPLE
    # Send a notification to all users that the password expires in 14 days or less using port 25
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -DaysBeforeExpire 14

.EXAMPLE
    # Simulate the notifications by doing the same as on Prod but sending them to specific user(s) and log the execution of the script on a CMTrace log
    New-ADPasswordExpiresNotification.ps1 -Simulate -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -To @('usera@domain.com', 'userb@domain.com') -DaysBeforeExpire 14 -LogIt

.EXAMPLE
    # Send a notification to all users that the password expires in 14 days or less using port 25 and log the execution of the script on a CMTrace log
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -DaysBeforeExpire 14 -LogIt

.EXAMPLE
    # Send a notification to the 200 first users that the password expires in 14 days or less using port 25
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -DaysBeforeExpire 14 -MailQuotaMax 200

.EXAMPLE
    # Send a notification to the 200 first users that the password expires in 14 days or less using port 25 and create a live report that will be exported to the same folder as the script
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -DaysBeforeExpire 14 -MailQuotaMax 200 -CreateLiveReport

.EXAMPLE
    # Send a notification to the 3 first users that the password expires in 8 days or less and that are on TestPassword AD Group using port 25 and create a live report that will be exported to the same folder as the script
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -DaysBeforeExpire 8 -ADGroup TestPassword -MailQuotaMax 10 -CreateLiveReport

.EXAMPLE
    # Create a report about the current AD users password expiration state
    New-ADPasswordExpiresNotification.ps1 -CreateADStateReport

.NOTES
    FileName : New-ADPasswordExpiresNotification.ps1
    Author   : Jonathan Mouco
    GitHub   : @Wavee7

    License  : MIT (https://github.com/Wavee7/PowerShell/blob/main/LICENSE)

    Version history :
    1.0.0 - (2022-02-07) - Script created
#>


#----------------------------------------#
# ---  -      Parameter Sets      -  --- #
#----------------------------------------#

[CmdletBinding(SupportsShouldProcess = $true)]

param(
    [Parameter(ParameterSetName = 'PROD', Mandatory = $true, HelpMessage = 'Set the script state to PROD')]
    [Switch]$Prod,

    [Parameter(ParameterSetName = 'SIMULATE', Mandatory = $true, HelpMessage = 'Set the script state to SIMULATE')]
    [Switch]$Simulate,

    [Parameter(ParameterSetName = 'REPORT', Mandatory = $true, HelpMessage = 'Set the script state to REPORT : Create a report of current password expiration state of AD users')]
    [Switch]$CreateADStateReport,

    [Parameter(ParameterSetName = 'PROD', Mandatory = $true, HelpMessage = 'SMTP Server Hostname or IP Address')]
    [Parameter(ParameterSetName = 'SIMULATE', Mandatory = $true)]
    [Parameter(ParameterSetName = 'REPORT')]
    [String]$SMTPServer,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'SMTP Server port')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Parameter(ParameterSetName = 'REPORT')]
    [Int]$SMTPPort = 25,

    [Parameter(ParameterSetName = 'PROD', Mandatory = $true, HelpMessage = 'eg "IT Support <support@domain.com>"')]
    [Parameter(ParameterSetName = 'SIMULATE', Mandatory = $true)]
    [Parameter(ParameterSetName = 'REPORT')]
    [String]$From,

    [Parameter(ParameterSetName = 'SIMULATE', Mandatory = $true, HelpMessage = 'Recipient to send the notification')]
    [Parameter(ParameterSetName = 'REPORT')]
    [String[]]$To,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Limit processing to specific users of an AD Group')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [String]$ADGroup,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Days before the expiration date as reference')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Int]$DaysBeforeExpire,

    [Parameter(ParameterSetName = 'SIMULATE', HelpMessage = 'Days before expiration as reference')]
    [Int[]]$DaysInterval,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Specify the maximum e-Mail quota per execution')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Int]$MailQuotaMax,

    [Parameter(HelpMessage = 'The script will create a CMTrace log')]
    [Switch]$LogIt,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Path to the log or report file (Default: Script path)')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Parameter(ParameterSetName = 'REPORT')]
    [String]$LogPath,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Create a report while on PROD or SIMULATE mode')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Switch]$CreateLiveReport,

    [Parameter(ParameterSetName = 'REPORT', HelpMessage = 'Path to the report file (Default: Script path)')]
    [String]$ReportPath
)

Begin {
    #----------------------------------------#
    # ---  -    Global Information    -  --- #
    #----------------------------------------#

    [System.Object]$objScriptInfo = [PSCustomObject]@{
        LogFileName    = $null
        LogPath        = $null
        ScriptRoot     = $null
        DateToday      = (Get-Date).ToLocalTime()
    }

    [System.Object]$objMailSettings = [PSCustomObject]@{
        Body          = $null
        SubjectPreFix = 'IT Department : '
        TextEncoding  = [System.Text.Encoding]::UTF8
    }

    [System.Object]$objEmailBodyFields = [PSCustomObject]@{
        Color              = '444444'
        DaysMessage        = $null
        BodyDaysMessage    = $null
        BodyDaysMessageOpt = $null
        FinalMessage       = 'IT Support remains at your disposal in case of difficulty.'
        Font               = 'Trebuchet MS'
        Name               = $null
        ExplanationLink    = 'Insert here a link to an explanatory web page'
        Signature          = 'IT Department'
        Size               = 'Normal'
    }

    [System.Object]$objStatistics = [PSCustomObject]@{
        TotalIntervalNotMatch = 0
        TotalEmailInvalid     = 0
        TotalNoExpirationDate = 0
        TotalNotExpired       = 0
        TotalNotified         = 0
        TotalNotOnADGroup     = 0
        TotalNotProcessed     = 0
        TotalChecked          = 0
    }


    # Set location and basic info
    Set-Location -Path $PSScriptRoot; $objScriptInfo.ScriptRoot = Get-Item -Path (Get-Location).Path
    [String]$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $objScriptInfo.LogFileName = "$(Get-Date -Format 'yyyy-MM-dd')_$($Script:PSCmdlet.ParameterSetName)_$scriptName.log"

    if($CreateADStateReport -or $CreateLiveReport) {
        [System.Array]$objReport = @()
        [String]$strReportPath = ''
        [String]$strReportFileName = "$(Get-Date -Format 'yyyy-MM-dd HHmmss')_$($Script:PSCmdlet.ParameterSetName)_$scriptName.csv"
    }

    # Set date and times info
    [DateTime]$dtScriptStart = $objScriptInfo.DateToday

    [TimeSpan]$dtTimeToMidnightD1 = New-TimeSpan -Start $dtScriptStart -End $dtScriptStart.Date.AddDays(1)
    [TimeSpan]$dtTimeToMidnightD2 = New-TimeSpan -Start $dtScriptStart -End $dtScriptStart.Date.AddDays(2)
}
Process {
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # *** -                               Function                               - *** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    function Get-EmailBody {
        <#
        .SYNOPSIS
            The Get-EmailBody provides the template of the e-Mail that will
            be sent to the user to notify

        .PARAMETER Parameters
            Object with all the parameters for the template

        .OUTPUTS
            Object with all requested properties
        #>

        [CmdletBinding()]

        [OutputType([String])]

        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Fields
        )

        [String]$locStrBody = ''


        $locStrBody += "
        <body>
            <font face=""$($Fields.Font)"" size=""$($Fields.Size)"" color=""$($Fields.Color)"">

                <p><i><b>This is an automated message, please do not reply.</i></b><br><br><br>

                Cher(e) $($Fields.Name),<br><br>"

        
                switch($Fields.BodyDaysMessageOpt) {
                    1 {
                        $locStrBody += "Your Windows password <b>$($Fields.BodyDaysMessage)</b>.<br><br>"

                        break
                    }

                    2 {
                        $locStrBody += "Your Windows password will expire on <b>$($Fields.BodyDaysMessage)</b>.<br><br>"

                        break
                    }
                }

                $locStrBody += "

                For more information on how to change your password, please refer to <a href=""$($Fields.ExplanationLink)"">this page<a/>.<br>


                <br><br>$($Fields.FinalMessage)<br><br>

                <b>$($Fields.Signature)</b></p>
            </font>
        </body>"


        Write-Output -InputObject $locStrBody
    }

    function Get-UserInfo {
        <#
        .SYNOPSIS
            The Get-UserInfo will fetch all the requested user info

        .PARAMETER ScriptInfo
            Object with the script parameters

        .PARAMETER ADUser
            Object with the AD User

        .OUTPUTS
            Object with all requested properties
        #>

        [CmdletBinding()]

        [OutputType([System.Object])]

        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$ScriptInfo,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Microsoft.ActiveDirectory.Management.ADAccount]$ADUser
        )

        [System.Object]$locObjUserInfo = [PSCustomObject]@{
            DaysBeforeExpire        = $null
            DaysBeforeExpireRound   = $null
            Email                   = $ADUser.emailaddress
            ExpiresOn               = $null
            IsOnADGroup             = $false
            Name                    = $ADUser.Name
            PasswordExpired         = $ADUser.PasswordExpired
            PasswordNeverExpires    = $ADUser.PasswordNeverExpires
            ResultantPasswordPolicy = Get-AduserResultantPasswordPolicy -Identity $ADUser
            SamAccountName          = $ADUser.SamAccountName
        }


        try {
            if(($locObjUserInfo.PasswordNeverExpires -eq $false) -and $locObjUserInfo.ResultantPasswordPolicy) {
                $locObjUserInfo.ExpiresOn = $([DateTime]::FromFileTime($ADUser.'msDS-UserPasswordExpiryTimeComputed'))
                $locObjUserInfo.DaysBeforeExpire = New-TimeSpan -Start $objScriptInfo.DateToday -End $locObjUserInfo.ExpiresOn
                $locObjUserInfo.DaysBeforeExpireRound = [System.Math]::Round($locObjUserInfo.DaysBeforeExpire.TotalDays)
            }

            if($ADGroup) {
                [System.Object]$locObjADGroupMembers = (Get-ADGroupMember -Identity $ADGroup -Recursive).SamAccountName
                $locObjUserInfo.IsOnADGroup = $locObjADGroupMembers -contains $locObjUserInfo.SamAccountName
            }
        }
        catch {}

        Write-Output -InputObject $locObjUserInfo
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

        .OUTPUTS
            None
        #>

        param(
            [Parameter(Mandatory = $true, ValueFromPipeline, HelpMessage = 'Message added to the log file.')]
            [ValidateNotNullOrEmpty()]
            [String]$Message,
            
            [Parameter(HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('1', '2', '3')]
            [String]$Severity = '1',

            [Parameter(Mandatory = $true, HelpMessage = 'Name of the log directory location.')]
            [ValidateNotNullOrEmpty()]
            [String]$LogsDirectory,

            [Parameter(Mandatory = $true, HelpMessage = 'Name of the log file that the entry will written to.')]
            [ValidateNotNullOrEmpty()]
            [String]$FileName,

            [Parameter(HelpMessage = 'Log the execution')]
            [Bool]$LogIt = $false
        )


        if($LogIt) {
            # Determine log file location
            $logFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName

            # Construct time stamp for log entry
            if(-not(Test-Path -Path 'variable:global:TimezoneBias')) {
                [String]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
                if($TimezoneBias -match '^-') {
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
    }



    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # * -                                   MAIN                                   - * #
    # ** --------------------------*-*----------------*-*-------------------------- ** #
    # **  ------------------*-*-*-*----------------------*-*-*-*------------------  ** #

    try {
        # Set log path
        if($LogPath) {
            if(Test-Path -Path $LogPath) {
                $objScriptInfo.LogPath = $LogPath

                "[START] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                "Log path set to : $LogPath" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            }
            else {
                $objScriptInfo.LogPath = $objScriptInfo.ScriptRoot

                "[START] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                'Log path is invalid' | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                "[END] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                EXIT 0
            }
        }
        else {
            $objScriptInfo.LogPath = $objScriptInfo.ScriptRoot

            "[START] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            "Log path set to : $($objScriptInfo.LogPath)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        }

        # Get Users From AD who are Enabled, Passwords Expire and are Not Currently Expired
        'Getting users from AD...' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        [System.Object]$objAllADUsers = Get-ADUser -Filter {(Enabled -eq $true)} -Properties Name, PasswordNeverExpires, PasswordExpired, EmailAddress, msDS-UserPasswordExpiryTimeComputed
        "Loaded successfully $($objAllADUsers.Count) AD users" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

        # Domain Default Password Policy Information
        'Domain Default Password Policy :' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "ComplexityEnabled      : $((Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "MinPasswordAge          : $((Get-ADDefaultDomainPasswordPolicy).MinPasswordAge)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "MaxPasswordAge         : $((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "MinPasswordLength     : $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "PasswordHistoryCount : $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt


# # #         Variables Init          # # #

        [System.Object]$objUserInfo = New-Object -TypeName System.Object

        [Int]$intADUsersCount = $objAllADUsers.Count

        [String]$strStatus = ''

        [Bool]$swProcessIt = $false


# # # # # # # # # # # # # # # # # # # # # #

        switch($Script:PSCmdlet.ParameterSetName) {
            {($PSItem -eq 'PROD') -or ($PSItem -eq 'SIMULATE')} {
                foreach($user in $objAllADUsers) {
                    "[$($objStatistics.TotalChecked + 1)/$intADUsersCount] Processing : $($user.SamAccountName)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                    $objUserInfo = Get-UserInfo -ScriptInfo $objScriptInfo -ADUser $user

# # #        Process Conditions        # # #

                    # Determine if the user should be processed
                    if($objUserInfo.DaysBeforeExpire -ne $null) {
                        if($objUserInfo.Email -ne $null) {
                            if([System.String]::IsNullOrEmpty($ADGroup) -or ($ADGroup -and $objUserInfo.IsOnADGroup)) {
                                if($DaysBeforeExpire) {
                                    if($objUserInfo.DaysBeforeExpire.TotalDays -le $DaysBeforeExpire) {
                                        $swProcessIt = $true
                                    }
                                    else {
                                        $strStatus = 'NotExpired'
                                        $objStatistics.TotalNotExpired += 1
                                        "$($objUserInfo.Name) is not expiring" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                        $swProcessIt = $false
                                    }
                                }
                                else {
                                    $swProcessIt = $true
                                }
                            }
                            else {
                                $strStatus = 'NotOnADGroup'
                                $objStatistics.TotalNotOnADGroup += 1
                                "$($objUserInfo.Name) is not on $ADGroup AD group" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                $swProcessIt = $false
                            }
                        }
                        else {
                            "$($objUserInfo.Name) e-Mail is invalid" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                            $strStatus = 'InvalidEmail'
                            $objStatistics.TotalEmailInvalid += 1

                            $swProcessIt = $false
                        }
                    }
                    else {
                        $strStatus = 'NoExpirationDate'
                        $objStatistics.TotalNoExpirationDate += 1
                        "$($objUserInfo.Name) does not have expiration date" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                        $swProcessIt = $false
                    }

                    # Notification Processes
                    if($swProcessIt) {

# # #         e-Mail Building         # # #

                        # Determine the message for the Day part
                        switch($objUserInfo.DaysBeforeExpire) {
                            {$objUserInfo.PasswordExpired} {
                                $objEmailBodyFields.DaysMessage = 'Your Windows password has expired'
                                $objEmailBodyFields.BodyDaysMessage = 'has expired'
                                $objEmailBodyFields.BodyDaysMessageOpt = 1

                                break
                            }
                            {$PSItem.TotalHours -lt $dtTimeToMidnightD1.TotalHours} {
                                $objEmailBodyFields.DaysMessage = "Your Windows password expires today at $('{0:HH}:{0:mm}' -f $objUserInfo.ExpiresOn)"
                                $objEmailBodyFields.BodyDaysMessage = "expires today at $('{0:HH}:{0:mm}' -f $objUserInfo.ExpiresOn)"
                                $objEmailBodyFields.BodyDaysMessageOpt = 1

                                break
                            }
                            {($PSItem.TotalHours -ge $dtTimeToMidnightD1.TotalHours) -and ($PSItem.TotalHours -lt $dtTimeToMidnightD2.TotalHours)} {
                                $objEmailBodyFields.DaysMessage = "Your Windows password expires tomorrow at $('{0:HH}:{0:mm}' -f $objUserInfo.ExpiresOn)"
                                $objEmailBodyFields.BodyDaysMessage = "expire tomorrow at $('{0:HH}:{0:mm}' -f $objUserInfo.ExpiresOn)"
                                $objEmailBodyFields.BodyDaysMessageOpt = 1

                                break
                            }
                            {$PSItem.TotalDays -gt 1} {
                                $objEmailBodyFields.DaysMessage = "Your Windows password expires in $($objUserInfo.DaysBeforeExpire.Days) days"
                                $objEmailBodyFields.BodyDaysMessage = $objUserInfo.ExpiresOn.ToString('dddd à HH:mm', [CultureInfo]'en-US')
                                $objEmailBodyFields.BodyDaysMessageOpt = 2

                                break
                            }
                        }

                        
                        $objEmailBodyFields.Name = $objUserInfo.Name
                        $objMailSettings.Body = Get-EmailBody -Fields $objEmailBodyFields

# # #           Notify User           # # #

                        if($Simulate.IsPresent) {
                            if($DaysInterval) {
                                if($DaysInterval -contains $objUserInfo.DaysBeforeExpireRound) {
                                    Send-Mailmessage -SMTPServer $SMTPServer -Port $SMTPPort -From $From -To $To -Subject ($objMailSettings.SubjectPreFix + $objEmailBodyFields.DaysMessage) -Body $objMailSettings.Body -BodyAsHtml -Priority High -Encoding $objMailSettings.TextEncoding

                                    $strStatus = 'SIMULATE:Notified'
                                    $objStatistics.TotalNotified += 1
                                    "SIMULATION : e-Mail sent to $($To -join ' ; ')" | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                                }
                                else {
                                    "The days before the password expiration for $($objUserInfo.SamAccountName) does not match DaysInterval" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                    $strStatus = 'IntervalNotMatch'
                                    $strStatus = 'NotExpired'
                                    $objStatistics.TotalIntervalNotMatch += 1
                                }
                            }
                            else {
                                Send-Mailmessage -SMTPServer $SMTPServer -Port $SMTPPort -From $From -To $To -Subject ($objMailSettings.SubjectPreFix + $objEmailBodyFields.DaysMessage) -Body $objMailSettings.Body -BodyAsHtml -Priority High -Encoding $objMailSettings.TextEncoding

                                $strStatus = 'SIMULATE:Notified'
                                $objStatistics.TotalNotified += 1
                                "SIMULATION : e-Mail sent to $($To -join ' ; ')" | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                            }
                        }
                        else {
                            Send-Mailmessage -SMTPServer $SMTPServer -Port $SMTPPort -From $From -To $objUserInfo.eMail -Subject ($objMailSettings.SubjectPreFix + $objEmailBodyFields.DaysMessage) -Body $objMailSettings.Body -BodyAsHtml -Priority High -Encoding $objMailSettings.TextEncoding

                            $strStatus = 'Notified'
                            $objStatistics.TotalNotified += 1
                            "$($objUserInfo.Email) - Notified" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                        }
                    }
                    else {
                        $objStatistics.TotalNotProcessed += 1
                    }


                    # Create live report if requested
                    if($CreateLiveReport) {
                        $objReport += [PSCustomObject]@{
                            Name                 = $objUserInfo.Name
                            SamAccountName       = $objUserInfo.SamAccountName
                            Email                = $objUserInfo.Email
                            PasswordNeverExpires = $objUserInfo.PasswordNeverExpires
                            DaysBeforeExpire     = $objUserInfo.DaysBeforeExpire
                            ExpiresOn            = $objUserInfo.ExpiresOn
                            Status               = $strStatus
                        }
                    }

                    $objStatistics.TotalChecked += 1

                    if($MailQuotaMax -and ($objStatistics.TotalNotified -ge $MailQuotaMax)) {
                        break
                    }
                }

                # Export live report if requested
                if($CreateLiveReport) {
                    if($ReportPath) {
                        $strReportPath = $ReportPath
                    }
                    else {
                        $strReportPath = "$($objScriptInfo.ScriptRoot)\$strReportFileName"
                    }

                    $objReport | Export-Csv -Path $strReportPath -NoTypeInformation -Delimiter ';'

                    "Report exported to $strReportPath" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                }

                break
            }


# # #      Create AD State Report     # # #

            {$PSItem -eq 'REPORT'} {
                # Set report path
                if($ReportPath) {
                    $strReportPath = $ReportPath
                }
                else {
                    $strReportPath = "$($objScriptInfo.ScriptRoot)\$strReportFileName"
                }

                # Build report
                'Building the report...' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                foreach($user in $objAllADUsers) {

                    # Fetch user data
                    $objUserInfo = Get-UserInfo -ScriptInfo $objScriptInfo -ADUser $user

                    "Processing $($objUserInfo.SamAccountName)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                    # Create the report object for the current user
                    $objReport += [PSCustomObject]@{
                        Name                 = $objUserInfo.Name
                        SamAccountName       = $objUserInfo.SamAccountName
                        Email                = $objUserInfo.Email
                        PasswordNeverExpires = $objUserInfo.PasswordNeverExpires
                        DaysBeforeExpire     = $objUserInfo.DaysBeforeExpireRound
                        ExpiresOn            = $objUserInfo.ExpiresOn
                    }
                }

                $objReport | Export-Csv -Path $strReportPath -NoTypeInformation -Delimiter ';'

                "Report exported to $strReportPath" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                break
            }
        }
    }
    catch {
        $_.Exception.Message | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    }
}
End {
    "Total Interval Not Match : $($objStatistics.TotalIntervalNotMatch)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total EmailInvalid : $($objStatistics.TotalEmailInvalid)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total No Expiration Date : $($objStatistics.TotalNoExpirationDate)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Not Expired : $($objStatistics.TotalNotExpired)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Notified : $($objStatistics.TotalNotified)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Not Processed : $($objStatistics.TotalNotProcessed)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Checked : $($objStatistics.TotalChecked)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

    [TimeSpan]$tsScriptTimeElapsed = New-TimeSpan -Start $dtScriptStart -End (Get-Date).ToLocalTime()
    "Script elapsed time : $("{0:hh}:{0:mm}:{0:ss}" -f $tsScriptTimeElapsed)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "[END] Execution of $scriptName.ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

    EXIT 0
}