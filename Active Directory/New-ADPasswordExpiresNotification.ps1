#requires -modules 'ActiveDirectory'

<#
.SYNOPSIS
    New-ADPasswordExpiresNotification notify AD users when their password are going to expire or has expired

.DESCRIPTION
    New-ADPasswordExpiresNotification notify AD users when their password are going to expire or has expired.
    It also permits to create an AD password state report and a live report.
    It is possible to personnalise the message for both internal and external users.

.EXAMPLE
    # Send a notification to all users that the password expires in 14 days or less. Use port 25; enUS culture
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture enUS -ConditionMode DaysBeforeExpire -Days 14

.EXAMPLE
    # Simulate the notifications by doing the same as on Prod but sending them to specific users. Log the execution of the script on a CMTrace log
    New-ADPasswordExpiresNotification.ps1 -Simulate -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -To usera@domain.com, userb@domain.com -Culture enUS -ConditionMode DaysBeforeExpire -Days 14 -LogIt

.EXAMPLE
    # Send a notification to all users that the password expires in 1, 3, 14 days. Use port 25; enUS and frFR culture; log the execution of the script on a remote CMTrace log
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture enUS, frFR -ConditionMode DaysInterval -Days 1, 3, 14 -LogIt -LogPath '\\contoso.com\logs'

.EXAMPLE
    # Send a notification to the 200 first users that the password expires in 14 days or less. Use port 25; frFR culture
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture frFR -ConditionMode DaysBeforeExpire 14 -MailQuotaMax 200

.EXAMPLE
    # Send a notification to all users that have a password policy on their profile and that the password expires. Use port 25; frFR and enUS culture; create a live report on the same folder as the script
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture frFR, enUS -ConditionMode ProcessAllWithPolicy -CreateLiveReport

.EXAMPLE
    # Send a notification to all users that the password expires in 1, 5, 10 days. Notify new users and set a password expiration date 15 days later from script execution date. Use port 25; enUS and frFR culture; create a CMTrace log and a live report on the same folder as the script
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture enUS, frFR -ConditionMode DaysInterval -Days 1, 5, 10 -NotifyNewUsers -ForceNewUserPasswordExpiresIn 15 -LogIt -CreateLiveReport

.EXAMPLE
    # Send a notification to all users that the password expires in 7 days or less and that are on specified ADGroup. Notify new users but don't set expiration date. Use port 25; enUS culture; create a live report on the same folder as the script
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture enUS -ConditionMode DaysBeforeExpire -Days 7 -ADGroup TestPasswordGroup -CreateLiveReport

.EXAMPLE
    # Simulate the notification to all users that the password expires in 3 days or less and that are on specified ADGroup. Simulate the notification for new users and force expiration 7 days later from the script execution date. Use port 25; enUS and frFR culture; log the execution of the script on a remote CMTrace log and create a remote live report
    New-ADPasswordExpiresNotification.ps1 -Prod -SMTPServer mail.domain.com -From 'IT Support <support@domain.com>' -Culture enUS, frFR -ConditionMode DaysBeforeExpire -Days 3 -ADGroup TestPasswordGroup -LogIt -LogPath '\\contoso.com\logs' -CreateLiveReport -ReportPath '\\contoso.com\logs'

.EXAMPLE
    # Create a report about the current AD users password expiration state
    New-ADPasswordExpiresNotification.ps1 -CreateADStateReport

.EXAMPLE
    # Create a remote report about the current AD users password expiration state
    New-ADPasswordExpiresNotification.ps1 -CreateADStateReport -ReportPath '\\contoso.com\logs'

.NOTES
    FileName : New-ADPasswordExpiresNotification.ps1
    Author   : Jonathan Mouco
    GitHub   : @Wavee7

    License  : MIT (https://github.com/Wavee7/PowerShell/blob/main/LICENSE)

    Version history :
    2.0.0 - (2022-03-02) - Specific e-Mail object and body contents can be set on object objEmailCulture
                         - Property InternalDomain of object objScriptInfo can be set to the domain part of the internal e-Mail addresses so the sent messages will be different if external AD users are affected by the password policy.
                         - The case 'User cannot change password' is now automatically unchecked for every user processed.
                         - Now the user can receive the notification on more than one language. The format is enUS, frFR, etc... For now, only this two languages are available.
                         - When $ADGroup is specified, users are now filtered before they are processed.
                         - It is now possible to integrate the password policy more progressively into a new environment.
                           The script will detect when a user have a password policy active but the 'Password never expires' is checked. It is considered as a 'New User'.
                           The user is notified with a message that says that a password policy is in place and that the expiration of password will take place at a specific date (Date now + ForceNewUserPasswordExpiresIn).
                           The expiration date will be written into the txt file with the SamAccountName so the script can verify if the date is reached for the new users.
                         - DaysBeforeExpire and DaysInterval are now part of script condition Mode. DaysInterval condition mode can be used in PROD and SIMULATE mode instead of SIMULATE only.
                         - You can use the switch 'NotifyNewUsers' to notify the new users. A txt file will be created on the root script folder with SamAccountNames already notified so the new users are only notified 1 time.
                         - Property NewUserExpiresGapMinutes can be configured on object objScriptInfo to add a delay from midnight of the expiration day to the desired time of expiration.
                         - You can use the switch 'ForceNewUserPasswordExpiresIn' to set 'Password never expires' case to false at specified date (Date now + Specified days).
    1.0.1 - (2022-02-11) - Minor text change.
    1.0.0 - (2022-02-07) - Script created.
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

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Specify the maximum e-Mail quota per execution')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Int]$MailQuotaMax,

    [Parameter(ParameterSetName = 'PROD', Mandatory = $true, HelpMessage = 'Culture of the subject and body message (Available : enUS, frFR). The first one will be the culture for the subject')]
    [Parameter(ParameterSetName = 'SIMULATE', Mandatory = $true)]
    [String[]]$Culture,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Script condition mode')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [ValidateSet('DaysBeforeExpire', 'DaysInterval', 'ProcessAllWithPolicy')]
    [String]$ConditionMode,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Days before expiration for DaysBeforeExpire condition mode or interval of days for DaysInverval condition mode')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Int[]]$Days,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Limit processing to specific users of an AD Group')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [String]$ADGroup,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Script will notify new users. New users are only notified 1 time.')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Switch]$NotifyNewUsers,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = "Days after the script execution at which the new users will be forced to change their password (Case 'Password never expires' will be unchecked).")]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Int]$ForceNewUserPasswordExpiresIn,

    [Parameter(HelpMessage = 'The script will create a CMTrace log')]
    [Switch]$LogIt,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Path to the log file (Default: Script path)')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Parameter(ParameterSetName = 'REPORT')]
    [String]$LogPath,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Create a report while on PROD or SIMULATE mode')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Switch]$CreateLiveReport,

    [Parameter(ParameterSetName = 'PROD', HelpMessage = 'Path to the report file (Default: Script path)')]
    [Parameter(ParameterSetName = 'SIMULATE')]
    [Parameter(ParameterSetName = 'REPORT')]
    [String]$ReportPath
)

Begin {
    #----------------------------------------#
    # ---  -    Global Information    -  --- #
    #----------------------------------------#

    [System.Object]$objScriptInfo = [PSCustomObject]@{
        NewUserExpiresGapMinutes = 120 # Delay between the notification and the effective expiration time

        DateToday   = (Get-Date).ToLocalTime()
        LogFileName = $null
        LogPath     = $null
        ReportPath  = $null
        ScriptName  = $null
        ScriptRoot  = $null
    }

    [System.Object]$objMailSettings = [PSCustomObject]@{
        Color          = '000000'
        Font           = 'Verdana'
        InternalDomain = '' # Write here your internal e-Mail domain (eg. '@contoso.com')
        Size           = 'Normal'

        Culture        = $Culture
        Body           = $null
        BodyTemplate   = $null
        UserEmail      = $null
        Subject        = $null
        TextEncoding   = [System.Text.Encoding]::UTF8
    }

    [System.Object]$objEmailCulture = [PSCustomObject]@{
        enUS =  [System.Object]$enUS = [PSCustomObject]@{
                    CorporateName            = "Contoso"
                    ITDepartmentName         = "IT"

                    LinkWordAt               = "at"
                    RenewPolicy              = '3 months'

                    SubjectPreFixInternal    = "IT Department -"
                    SubjectNewUserInternal   = "New password policy"
                    SubjectExpiredInternal   = "Your password has expired"
                    SubjectTodayInternal     = "Your password expires today at"
                    SubjectTomorrowInternal  = "Your password expires tomorrow at"
                    SubjectInFewDaysInternal = "Your password expires in about [Days] :"

                    SubjectPreFixExternal    = "IT Security Notification -"
                    SubjectNewUserExternal   = "New password policy for your access"
                    SubjectExpiredExternal   = "Your access password has expired"
                    SubjectTodayExternal     = "Your access password expires today at"
                    SubjectTomorrowExternal  = "Your access password expires tomorrow at"
                    SubjectInFewDaysExternal = "Your access password expires in about [Days] :"

                    BodyAutomatedMsg         = 'This is an automated message, please do not reply'
                    BodyDear                 = 'Dear'

                    ExplanationLink          = "(Insert here a link to an explanatory web page)"

                    FinalMessageInternal     = "IT Support remains at your disposal in case of difficulty."
                    FinalMessageExternal     = "In case of difficulty please contact our IT team."
                    SignatureInternal        = "IT Department"
                    SignatureExternal        = 'Contoso Corporation'

                    BodyDaysMessage          = $null
                    BodyTemplate             = $null
                    ExpiresOn                = $null
                }

        frFR =  [System.Object]$frFR = [PSCustomObject]@{
                    CorporateName            = "Contoso"
                    ITDepartmentName         = "IT"

                    LinkWordAt               = "à"
                    RenewPolicy              = '3 mois'

                    SubjectPreFixInternal    = "Département IT -"
                    SubjectNewUserInternal   = "Nouvelle politique des mots de passe"
                    SubjectExpiredInternal   = "Votre mot de passe a expiré"
                    SubjectTodayInternal     = "Votre mot de passe expirera aujourd'hui à"
                    SubjectTomorrowInternal  = "Votre mot de passe expirera demain à"
                    SubjectInFewDaysInternal = "Votre mot de passe expirera dans environ [Jours] :"

                    SubjectPreFixExternal    = "Notification de sécurité IT -"
                    SubjectNewUserExternal   = "Nouvelle politique de mot de passe pour votre accès"
                    SubjectExpiredExternal   = "Votre mot de passe d'accès a expiré"
                    SubjectTodayExternal     = "Votre mot de passe d'accès expire aujourd'hui à"
                    SubjectTomorrowExternal  = "Votre mot de passe d'accès expire demain à"
                    SubjectInFewDaysExternal = "Votre mot de passe d'accès expire dans environ [Jours] :"

                    BodyAutomatedMsg         = 'Ceci est un message automatique, veuillez ne pas répondre'
                    BodyDear                 = 'Cher(e)'

                    ExplanationLink          = "(Inserez ici un lien vers un article explicatif)"

                    FinalMessageInternal     = "L'équipe IT reste à votre disposition pour toute assistance en cas de problème."
                    FinalMessageExternal     = "En cas de problème, veuillez contacter notre équipe IT."
                    SignatureInternal        = "Département IT"
                    SignatureExternal        = 'Contoso Corporation'

                    BodyDaysMessage          = $null
                    BodyTemplate             = $null
                    ExpiresOn                = $null
                }
    }


    [System.Object]$objEmailBodyFields = [PSCustomObject]@{
        BodyTemplate = $null
        Name         = $null
    }

    [System.Object]$objStatistics = [PSCustomObject]@{
        TotalEmailInvalid = 0
        TotalNewUser      = 0
        TotalNotExpired   = 0
        TotalNotified     = 0
        TotalNotNotified  = 0
        TotalNotOnADGroup = 0
        TotalChecked      = 0
    }


    # Set location and basic info
    Set-Location -Path $PSScriptRoot; $objScriptInfo.ScriptRoot = Get-Item -Path (Get-Location).Path
    $objScriptInfo.ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $objScriptInfo.LogFileName = "$(Get-Date -Format 'yyyy-MM-dd')_$($Script:PSCmdlet.ParameterSetName)_$($objScriptInfo.ScriptName).log"

    if($CreateADStateReport -or $CreateLiveReport) {
        [System.Array]$objReport = @()
        [String]$strReportPath = ''
        [String]$strReportFileName = "$(Get-Date -Format 'yyyy-MM-dd HHmmss')_$($Script:PSCmdlet.ParameterSetName)_$($objScriptInfo.ScriptName).csv"

        # Set report path
        if($ReportPath) {
            $objScriptInfo.ReportPath = "$ReportPath\$strReportFileName"
        }
        else {
            $objScriptInfo.ReportPath = "$($objScriptInfo.ScriptRoot)\$strReportFileName"
        }
    }

    [System.Array]$objAllADUsers = @()
    [System.Array]$arrADGroupMembers = @()

    [System.Object]$objADDefaultPasswordPolicy = New-Object -TypeName System.Object

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

        .PARAMETER MailSettings
            Object with the global settings for mails

        .PARAMETER Fields
            Object with fields for each culture

        .PARAMETER Culture
            Object with culture specifics

        .OUTPUTS
            Object with all requested properties
        #>

        [OutputType([String])]

        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$MailSettings,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Fields,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Culture
        )

        [Int]$locIntCultureCount = 0
        [String]$locStrExpiresOn = ''

        [String]$locStrBody = "
            <body>
                <font face=""$($MailSettings.Font)"" size=""$($MailSettings.Size)"" color=""$($MailSettings.Color)"">"


        foreach($currentCulture in $MailSettings.Culture) {
            $locStrBody += "<p><i><b>$($Culture."$($currentCulture)".BodyAutomatedMsg)</i></b><br><br><br>$($Culture."$($currentCulture)".BodyDear) $($Fields.Name),<br><br>"

            # Check if the current user is internal or external
            if($MailSettings.UserEmail.Contains($MailSettings.InternalDomain)) {

# # #      Internal Domain User       # # #

                switch -Wildcard ($currentCulture) {

# # #   Internal Domain User - enUS   # # #

                    'enUS' {
                        switch -Wildcard ($MailSettings.BodyTemplate) {
                            'NewUser' {
                                # First frase
                                $locStrBody += "In order to strengthen computer security at $($Culture."$($currentCulture)".CorporateName), the $($Culture."$($currentCulture)".ITDepartmentName) department has implemented a new password policy for logging you into your Windows computer.<br><br>"

                                # Second frase
                                if($Culture."$($currentCulture)".ExpiresOn) {
                                    $locStrBody += "You are receiving this message because you are now affected by this new policy and your password will expire on the following date : <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"
                                }
                                else {
                                    $locStrBody += "You are receiving this message because you are now affected by this new policy. You will receive another notification when your password is about to expire.<br><br>"
                                }

                                # Third frase
                                $locStrBody += "You have the possibility to change your password before this date in order to avoid any problem. Your password will expire $($Culture."$($currentCulture)".RenewPolicy) from the date of change. "

                                # Fourth frase
                                $locStrBody += "For more information on the policy and on the procedure to follow in order to change your password, please refer to <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">this page<a/>.<br><br><br>"

                                break
                            }

                            'Expired' {
                                # First frase
                                $locStrBody += "Your Windows password <b>has expired</b>.<br><br>"

                                # Second frase
                                $locStrBody += " For more information on how to change your password, please refer to <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">this page<a/>.<br><br><br>"

                                break
                            }

                            'Today' {
                                # First frase
                                $locStrBody += "Your Windows computer password expires <b>today at $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " For more information on how to change your password, please refer to <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">this page<a/>.<br><br><br>"

                                break
                            }

                            'Tomorrow' {
                                # First frase
                                $locStrBody += "Your Windows computer password will expire <b>tomorrow at $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " For more information on how to change your password, please refer to <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">this page<a/>.<br><br><br>"

                                break
                            }

                            'InFewDays' {
                                # First frase
                                $locStrBody += "Your Windows computer password will expire on <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " For more information on how to change your password, please refer to <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">this page<a/>.<br><br><br>"

                                break
                            }
                        }

                        break
                    }

# # #   Internal Domain User - frFR   # # #

                    'frFR' {
                        switch -Wildcard ($MailSettings.BodyTemplate) {
                            'NewUser' {
                                # First frase
                                $locStrBody += "Afin de renforcer la sécurité informatique à $($Culture."$($currentCulture)".CorporateName), le département $($Culture."$($currentCulture)".ITDepartmentName) a mit en place une nouvelle politique de mot de passe pour vous loguer sur votre ordinateur Windows.<br><br>"

                                # Second frase
                                if($Culture."$($currentCulture)".ExpiresOn) {
                                    $locStrBody += "Vous recevez ce message car vous êtes maintenant affecté par cette nouvelle politique et votre mot de passe expirera à la date suivante : <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"
                                }
                                else {
                                    $locStrBody += "Vous recevez ce message car vous êtes maintenant affecté par cette nouvelle politique. Vous recevrez une nouvelle notification lorsque votre mot de passe arrivera à la date d'expiration.<br><br>"
                                }

                                # Third frase
                                $locStrBody += "Vous avez la possibilité de modifier votre mot de passe avant cette date afin d'éviter tout problème. Votre mot de passe expirera ensuite $($Culture."$($currentCulture)".RenewPolicy) plus tard."

                                # Fourth frase
                                $locStrBody += " Pour obtenir plus d'informations sur la politique et sur la procédure à suivre afin de modifier votre mot de passe, merci de vous référez à <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">cet article<a/>.<br><br><br>"

                                break
                            }

                            'Expired' {
                                # First frase
                                $locStrBody += "Votre mot de passe Windows <b>a expiré</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Pour obtenir plus d'informations sur la procédure à suivre afin de modifier votre mot de passe, merci de vous référez à <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">cet article<a/>.<br><br><br>"

                                break
                            }

                            'Today' {
                                # First frase
                                $locStrBody += "Votre mot de passe de votre ordinateur Windows expirera <b>aujourd'hui à $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Pour obtenir plus d'informations sur la procédure à suivre afin de modifier votre mot de passe, merci de vous référez à <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">cet article<a/>.<br><br><br>"

                                break
                            }

                            'Tomorrow' {
                                # First frase
                                $locStrBody += "Votre mot de passe de votre ordinateur Windows expirera <b>demain à $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Pour obtenir plus d'informations sur la procédure à suivre afin de modifier votre mot de passe, merci de vous référez à <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">cet article<a/>.<br><br><br>"

                                break
                            }

                            'InFewDays' {
                                # First frase
                                $locStrBody += "Votre mot de passe de votre ordinateur Windows expirera le <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Pour obtenir plus d'informations sur la procédure à suivre afin de modifier votre mot de passe, merci de vous référez à <a href=""$($Culture."$($currentCulture)".ExplanationLink)"">cet article<a/>.<br><br><br>"

                                break
                            }
                        }

                        break
                    }
                }

                # Third frase
                $locStrBody += "$($Culture."$($currentCulture)".FinalMessageInternal)"

                # Signature
                $locStrBody += "<br><br>$($Culture."$($currentCulture)".SignatureInternal)</b></p>"
            }
            else {

# # #      External Domain User       # # #

                switch -Wildcard ($currentCulture) {

# # #   External Domain User - enUS   # # #

                    'enUS' {
                        switch -Wildcard ($MailSettings.BodyTemplate) {
                            'NewUser' {
                                # First frase
                                $locStrBody += "In order to strengthen computer security at $($Culture."$($currentCulture)".CorporateName), the $($Culture."$($currentCulture)".ITDepartmentName) department has implemented a new password policy for your access to our internal network.<br><br>"

                                # Second frase
                                if($Culture."$($currentCulture)".ExpiresOn) {
                                    $locStrBody += "You are receiving this message because you are now affected by this new policy and your password will expire on the following date : <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"
                                }
                                else {
                                    $locStrBody += "You are receiving this message because you are now affected by this new policy. You will receive another notification when your password is about to expire.<br><br>"
                                }

                                # Third frase
                                $locStrBody += "You have the possibility to change your password before this date in order to avoid any problem. Your password will expire $($Culture."$($currentCulture)".RenewPolicy) from the date of change.<br><br><br>"

                                break
                            }

                            'Expired' {
                                # First frase
                                $locStrBody += "Your password to access our network <b>has expired</b>.<br><br>"

                                # Second frase
                                $locStrBody += " If you connect to $($Culture."$($currentCulture)".CorporateName) network through a VPN, you will be prompted to change your password on the next login attempt.<br><br><br>"

                                break
                            }

                            'Today' {
                                # First frase
                                $locStrBody += "Your password to access our netowork expires <b>today at $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " If you connect to $($Culture."$($currentCulture)".CorporateName) network through a VPN, you will be prompted to change your password on the first login attempt right after the expiration date.<br><br><br>"

                                break
                            }

                            'Tomorrow' {
                                # First frase
                                $locStrBody += "Your password to access our network will expire <b>tomorrow at $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " If you connect to $($Culture."$($currentCulture)".CorporateName) network through a VPN, you will be prompted to change your password on the first login attempt right after the expiration date.<br><br>"

                                break
                            }

                            'InFewDays' {
                                # First frase
                                $locStrBody += "Your password to access our network will expire on <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " If you connect to $($Culture."$($currentCulture)".CorporateName) network through a VPN, you will be prompted to change your password on the first login attempt right after the expiration date.<br><br><br>"

                                break
                            }
                        }


                        break
                    }

# # #   External Domain User - frFR   # # #

                    'frFR' {
                        switch -Wildcard ($MailSettings.BodyTemplate) {
                            'NewUser' {
                                # First frase
                                $locStrBody += "Afin de renforcer la sécurité informatique à $($Culture."$($currentCulture)".CorporateName), le département $($Culture."$($currentCulture)".ITDepartmentName) a mis en place une nouvelle politique de mot de passe pour votre accès à notre réseau interne.<br><br>"

                                # Second frase
                                if($Culture."$($currentCulture)".ExpiresOn) {
                                    $locStrBody += "Vous recevez ce message car vous êtes maintenant affecté par cette nouvelle politique et votre mot de passe expirera à la date suivante : <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"
                                }
                                else {
                                    $locStrBody += "Vous recevez ce message car vous êtes maintenant affecté par cette nouvelle politique. Vous recevrez une nouvelle notification lorsque votre mot de passe arrivera à la date d'expiration.<br><br>"
                                }

                                # Third frase
                                $locStrBody += "Vous avez la possibilité de modifier votre mot de passe avant cette date afin d'éviter tout problème. Votre mot de passe expirera ensuite $($Culture."$($currentCulture)".RenewPolicy) plus tard.<br><br><br>"

                                break
                            }

                            'Expired' {
                                # Frist frase
                                $locStrBody += "Votre mot de passe d'accès à notre réseau <b>a expiré</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Si vous accédez au réseau de $($Culture."$($currentCulture)".CorporateName) par l'intermédiaire d'un VPN, vous serez invité à changer votre mot de passe dès la prochaine tentative de connection.<br><br><br>"

                                break
                            }

                            'Today' {
                                # First frase
                                $locStrBody += "Votre mot de passe d'accès à notre réseau expirera <b>aujourd'hui à $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Si vous accédez au réseau de $($Culture."$($currentCulture)".CorporateName) par l'intermédiaire d'un VPN, vous serez invité à changer votre mot de passe dès la première tentative de connexion qui suit la date d'expiration.<br><br><br>"

                                break
                            }

                            'Tomorrow' {
                                # First frase
                                $locStrBody += "Votre mot de passe d'accès à notre réseau expirera <b>demain à $($Culture."$($currentCulture)".BodyDaysMessage)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Si vous accédez au réseau de $($Culture."$($currentCulture)".CorporateName) par l'intermédiaire d'un VPN, vous serez invité à changer votre mot de passe dès la première tentative de connexion qui suit la date d'expiration.<br><br><br>"

                                break
                            }

                            'InFewDays' {
                                # First frase
                                $locStrBody += "Votre mot de passe d'accès à notre réseau expirera le <b>$($Culture."$($currentCulture)".ExpiresOn)</b>.<br><br>"

                                # Second frase
                                $locStrBody += " Si vous accédez au réseau de $($Culture."$($currentCulture)".CorporateName) par l'intermédiaire d'un VPN, vous serez invité à changer votre mot de passe dès la première tentative de connexion qui suit la date d'expiration.<br><br><br>"

                                break
                            }
                        }


                        break
                    }
                }

                # Final frase
                $locStrBody += "$($Culture."$($currentCulture)".FinalMessageExternal)"

                # Signature
                $locStrBody += "<br><br>$($Culture."$($currentCulture)".SignatureExternal)</b></p>"
            }


            if(++$locIntCultureCount -le ($MailSettings.Culture.Count - 1)) {
                $locStrBody += '<br><br>***************************************************************************************************************<br><br><br>'
            }
        }

        $locStrBody += "</font>
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

        .PARAMETER ADGroupMembers
            Array of members that are on ADGroup if specified

        .OUTPUTS
            Object with all requested properties
        #>

        [OutputType([System.Object])]

        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$ScriptInfo,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Microsoft.ActiveDirectory.Management.ADAccount]$ADUser,

            [Parameter(Mandatory = $false)]
            [System.Array]$ADGroupMembers
        )

        [System.Object]$locObjUserInfo = [PSCustomObject]@{
            DaysBeforeExpire        = $null
            DaysBeforeExpireRound   = $null
            Email                   = $ADUser.emailaddress
            ExpiresOn               = $null
            Name                    = $ADUser.Name
            WithPolicyNoExpiration  = $false
            PasswordExpired         = $ADUser.PasswordExpired
            PasswordNeverExpires    = $ADUser.PasswordNeverExpires
            CannotChangePassword    = $ADUser.CannotChangePassword
            ResultantPasswordPolicy = Get-AduserResultantPasswordPolicy -Identity $ADUser
            SamAccountName          = $ADUser.SamAccountName
        }


        try {
            if($locObjUserInfo.ResultantPasswordPolicy) {
                if(!$locObjUserInfo.PasswordNeverExpires) {
                    $locObjUserInfo.ExpiresOn = $([DateTime]::FromFileTime($ADUser.'msDS-UserPasswordExpiryTimeComputed'))
                    $locObjUserInfo.DaysBeforeExpire = New-TimeSpan -Start $objScriptInfo.DateToday -End $locObjUserInfo.ExpiresOn
                    $locObjUserInfo.DaysBeforeExpireRound = [System.Math]::Round($locObjUserInfo.DaysBeforeExpire.TotalDays)
                }
                else {
                    $locObjUserInfo.WithPolicyNoExpiration = $true
                }
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

# # #          Set log path           # # #

        if($LogPath) {
            if(Test-Path -Path $LogPath) {
                $objScriptInfo.LogPath = $LogPath

                "[START] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                "Log path set to : $LogPath" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            }
            else {
                $objScriptInfo.LogPath = $objScriptInfo.ScriptRoot

                "[START] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                'Log path is invalid' | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                "[END] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                EXIT 0
            }
        }
        else {
            $objScriptInfo.LogPath = $objScriptInfo.ScriptRoot

            "[START] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            "Log path set to : $($objScriptInfo.LogPath)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        }


# # #      Test some conditions       # # #

        # Verify that Days parameter is present while on DaysBeforeExpire and DaysInterval Condition Mode
        if((($ConditionMode -eq 'DaysBeforeExpire') -or ($ConditionMode -eq 'DaysInterval')) -and !$Days) {
            "You should set 'Days' parameter when $ConditionMode Condition mode is used" | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            "[END] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

            EXIT 0
        }

        # Verify that Culture parameter contain available cultures in script
        foreach($cult in $objMailSettings.Culture) {
            if(!$objEmailCulture."$($cult)") {
                "Culture '$($cult)' is not available" | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                "[END] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                EXIT 0
            }
        }


# # #      Get Enabled AD Users       # # #

        'Getting users from AD...' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        [System.Object]$objTempAllADUsers = Get-ADUser -Filter {(Enabled -eq $true)} -Properties Name, PasswordNeverExpires, CannotChangePassword, PasswordExpired, EmailAddress, msDS-UserPasswordExpiryTimeComputed
        "Loaded $($objTempAllADUsers.Count) AD users" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

        # If ADGroup is specified, the AD Users are filtered
        if($ADGroup) {
            # Get members of ADGroup
            $arrADGroupMembers = (Get-ADGroupMember -Identity $ADGroup -Recursive).SamAccountName

            # Filter AD users
            $objAllADUsers = $objTempAllADUsers | Where-Object {$arrADGroupMembers -contains $_.SamAccountName}

            "$($objTempAllADUsers.Count - $objAllADUsers.Count) were filtered out as they are not on specified ADGroup" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            $objStatistics.TotalNotOnADGroup = $objTempAllADUsers.Count - $objAllADUsers.Count
        }
        else {
            $objAllADUsers = $objTempAllADUsers
        }

        # Domain Default Password Policy Information
        $objADDefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
        '***** Domain Default Password Policy *****' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "ComplexityEnabled $(':'.PadLeft(7)) $($objADDefaultPasswordPolicy.ComplexityEnabled)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "MinPasswordAge $(':'.PadLeft(10)) $($objADDefaultPasswordPolicy.MinPasswordAge)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "MaxPasswordAge $(':'.PadLeft(9)) $($objADDefaultPasswordPolicy.MaxPasswordAge)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "MinPasswordLength $(':'.PadLeft(5)) $($objADDefaultPasswordPolicy.MinPasswordLength)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        "PasswordHistoryCount $(':'.PadLeft(0)) $($objADDefaultPasswordPolicy.PasswordHistoryCount)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
        '******************************************' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt


# # #         Variables Init          # # #

        [System.Object]$objUserInfo = New-Object -TypeName System.Object

        if($NotifyNewUsers.IsPresent) {
            [System.Array]$arrNewUsersNotified = @()


            if($Simulate.IsPresent) {
                [String]$strNewUsersNotifiedPath = "$($objScriptInfo.ScriptRoot)\SIMULATE_NewUsersNotified.txt"
            }
            else {
                [String]$strNewUsersNotifiedPath = "$($objScriptInfo.ScriptRoot)\NewUsersNotified.txt"
            }

            if(Test-Path -Path $strNewUsersNotifiedPath) {
                $arrNewUsersNotified = Get-Content -Path $strNewUsersNotifiedPath

                "Loaded $($arrNewUsersNotified.Count) new users notified" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            }
            else {
                New-Item -Path $strNewUsersNotifiedPath -ItemType File -Force | Out-Null

                "'$(Split-Path -Path $strNewUsersNotifiedPath -Leaf)' has been created on '$(Split-Path -Path $strNewUsersNotifiedPath)'" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
            }
        }

        [String]$strStatus = ''
        [String]$strStatusNotification = ''
        [String]$strNewUserExpiresDate = ''

        [System.Array]$arrNewUsersContentToAdd = @()

        [Bool]$swProcessIt = $false


# # # # # # # # # # # # # # # # # # # # # #

        switch($Script:PSCmdlet.ParameterSetName) {
            {($PSItem -eq 'PROD') -or ($PSItem -eq 'SIMULATE')} {
                foreach($user in $objAllADUsers) {
                    "[$($objStatistics.TotalChecked + 1)/$($objAllADUsers.Count)] Processing : $($user.SamAccountName)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                    $objUserInfo = Get-UserInfo -ScriptInfo $objScriptInfo -ADUser $user

# # #        Process Conditions       # # #

                    if($objUserInfo.Email) {
                        if(!$objUserInfo.WithPolicyNoExpiration) {
                            switch -Wildcard ($ConditionMode) {
                                'DaysBeforeExpire' {
                                    if($objUserInfo.DaysBeforeExpire.TotalDays -le $Days[0]) {
                                        $swProcessIt = $true
                                    }
                                    else {
                                        $strReason = 'NotExpired'
                                        $objStatistics.TotalNotExpired += 1
                                        "$($objUserInfo.Name) is not expiring" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                        $swProcessIt = $false
                                    }
                                }

                                'DaysInterval' {
                                    if($Days -contains $objUserInfo.DaysBeforeExpireRound) {
                                        $swProcessIt = $true
                                    }
                                    else {
                                        $strReason = 'NotExpired'
                                        $objStatistics.TotalNotExpired += 1
                                        "$($objUserInfo.Name) is not expiring" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                        $swProcessIt = $false
                                    }

                                    break
                                }

                                'ProcessAllWithPolicy' {
                                    if(!$objUserInfo.PasswordNeverExpires -or $objUserInfo.WithPolicyNoExpiration) {
                                        $swProcessIt = $true
                                    }
                                    else {
                                        $swProcessIt = $false
                                    }

                                    break
                                }
                            }
                        }
                        else {
                            if(!$arrNewUsersNotified -or !($arrNewUsersNotified | Where-Object {$_ -like "$($objUserInfo.SamAccountName)|*"})) {
                                "$($objUserInfo.Name) is a new user" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                # Set expiration for new User if requested
                                if($ForceNewUserPasswordExpiresIn) {
                                    $objUserInfo.ExpiresOn = $objScriptInfo.DateToday.Date.AddDays($ForceNewUserPasswordExpiresIn).AddMinutes($objScriptInfo.NewUserExpiresGapMinutes)

                                    "Expiration date for '$($objUserInfo.SamAccountName)' set to '$('{0:dd}.{0:MM}.{0:yyyy} {0:HH}:{0:mm}' -f $objUserInfo.ExpiresOn)'" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                                }
                                else {
                                    "Expiration date for '$($objUserInfo.SamAccountName)' not set" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                                }

                                # Should the new user be notified ?
                                if($NotifyNewUsers.IsPresent) {
                                    $strReason = 'NewUser'

                                    $swProcessIt = $true
                                }
                                else {
                                    $strReason = 'NewUserNotNotified'
                                    'New users are not notified' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                    $swProcessIt = $false
                                }
                            }
                            else {
                                # Get expiration date for current New User
                                $strNewUserExpiresDate = ($arrNewUsersNotified | Where-Object {$_ -like "$($objUserInfo.SamAccountName)|*"}).Split('|')[1]

                                if($strNewUserExpiresDate) {
                                    $objUserInfo.ExpiresOn = ([DateTime]::ParseExact($strNewUserExpiresDate, 'dd.MM.yyyy HH:mm', $null))

                                    # Uncheck the case 'Password never expires' on AD if date is reached
                                    if($objUserInfo.ExpiresOn -le $objScriptInfo.DateToday) {
                                        if($Simulate.IsPresent) {
                                            "SIMULATION : 'Password never expires' is now unchecked for '$($objUserInfo.SamAccountName)'" | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                                        }
                                        else {
                                            Set-ADUser -Identity $objUserInfo.SamAccountName -PasswordNeverExpires $false

                                            "'Password never expires' is now unchecked for '$($objUserInfo.SamAccountName)'" | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                                        }
                                    }
                                }

                                $strReason = 'NewUserAlreadyNotified'
                                "$($objUserInfo.Name) new user already notified" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                                $swProcessIt = $false
                            }

                            $objStatistics.TotalNewUser += 1
                        }
                    }
                    else {
                        "$($objUserInfo.Name) e-Mail is invalid" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                        $strReason = 'InvalidEmail'
                        $objStatistics.TotalEmailInvalid += 1

                        $swProcessIt = $false
                    }

                    # Build the Expire date and body days message for each culture
                    foreach($cult in $objMailSettings.Culture) {
                        if($objUserInfo.ExpiresOn) {
                            $objEmailCulture."$($cult)".ExpiresOn = $objUserInfo.ExpiresOn.ToString("dddd dd.MM.yyyy `'$($objEmailCulture."$($cult)".LinkWordAt)`' HH:mm", [CultureInfo]"$($cult)".Insert(2, '-'))
                            $objEmailCulture."$($cult)".BodyDaysMessage = $('{0:HH}:{0:mm}' -f $objUserInfo.ExpiresOn)
                        }
                        else {
                            $objEmailCulture."$($cult)".ExpiresOn = $null
                            $objEmailCulture."$($cult)".BodyDaysMessage = $null
                        }
                    }

                    # Notification Processes
                    if($swProcessIt) {

# # #         e-Mail Building         # # #

                        # Build subject and set body template to use
                        switch($objUserInfo) {
                            # New User
                            {$PSItem.WithPolicyNoExpiration} {
                                if($objUserInfo.Email.Contains($objMailSettings.InternalDomain)) {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixInternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectNewUserInternal)"
                                }
                                else {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixExternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectNewUserExternal)"
                                }

                                $objMailSettings.BodyTemplate = 'NewUser'

                                break
                            }

                            # Password expired
                            {$PSItem.PasswordExpired} {
                                if($objUserInfo.Email.Contains($objMailSettings.InternalDomain)) {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixInternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectExpiredInternal)"
                                }
                                else {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixExternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectExpiredExternal)"
                                }

                                $objMailSettings.BodyTemplate = 'Expired'

                                break
                            }

                            # Password expires today
                            {$PSItem.DaysBeforeExpire.TotalHours -lt $dtTimeToMidnightD1.TotalHours} {
                                if($objUserInfo.Email.Contains($objMailSettings.InternalDomain)) {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixInternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectTodayInternal) $('{0:HH}:{0:mm}' -f $PSItem.ExpiresOn)"
                                }
                                else {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixExternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectTodayExternal) $('{0:HH}:{0:mm}' -f $PSItem.ExpiresOn)"
                                }

                                $objMailSettings.BodyTemplate = 'Today'

                                break
                            }

                            # Password expires tomorrow
                            {($PSItem.DaysBeforeExpire.TotalHours -ge $dtTimeToMidnightD1.TotalHours) -and ($PSItem.DaysBeforeExpire.TotalHours -lt $dtTimeToMidnightD2.TotalHours)} {
                                if($objUserInfo.Email.Contains($objMailSettings.InternalDomain)) {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixInternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectTomorrowInternal) $('{0:HH}:{0:mm}' -f $PSItem.ExpiresOn)"
                                }
                                else {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixExternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectTomorrowExternal) $('{0:HH}:{0:mm}' -f $PSItem.ExpiresOn)"
                                }

                                $objMailSettings.BodyTemplate = 'Tomorrow'

                                break
                            }

                            # Password expires in more than 1 day
                            {$PSItem.DaysBeforeExpire.TotalDays -gt 1} {
                                if($objUserInfo.Email.Contains($objMailSettings.InternalDomain)) {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixInternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectInFewDaysInternal) $($PSItem.DaysBeforeExpire.Days)"
                                }
                                else {
                                    $objMailSettings.Subject = "$($objEmailCulture."$($objMailSettings.Culture[0])".SubjectPreFixExternal) $($objEmailCulture."$($objMailSettings.Culture[0])".SubjectInFewDaysExternal) $($PSItem.DaysBeforeExpire.Days)"
                                }

                                $objMailSettings.BodyTemplate = 'InFewDays'

                                break
                            }
                        }

                        
                        $objEmailBodyFields.Name = $objUserInfo.Name
                        $objMailSettings.UserEmail = $objUserInfo.Email
                        $objMailSettings.Body = Get-EmailBody -MailSettings $objMailSettings -Fields $objEmailBodyFields -Culture $objEmailCulture

# # #           Notify User           # # #

                        if($Simulate.IsPresent) {
                            Send-Mailmessage -SMTPServer $SMTPServer -Port $SMTPPort -From $From -To $To -Subject "$($objMailSettings.Subject)" -Body $objMailSettings.Body -BodyAsHtml -Priority High -Encoding $objMailSettings.TextEncoding

                            $strStatusNotification = 'SIMULATE:Notified'
                            $objStatistics.TotalNotified += 1
                            "SIMULATION : e-Mail sent to $($To -join ' ; ')" | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                        }
                        else {
                            Send-Mailmessage -SMTPServer $SMTPServer -Port $SMTPPort -From $From -To $objUserInfo.eMail -Subject "$($objMailSettings.Subject)" -Body $objMailSettings.Body -BodyAsHtml -Priority High -Encoding $objMailSettings.TextEncoding

                            $strStatusNotification = 'Notified'
                            $objStatistics.TotalNotified += 1
                            "$($objUserInfo.Email) - Notified" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                        }

# # #           Extra Stuff           # # #

                        # Uncheck 'User cannot change password' if present
                        if($objUserInfo.CannotChangePassowrd) {
                            Set-ADUser -Identity $objUserInfo.SamAccountName -CannotChangePassword $false

                            "'User cannot change password' is now unchecked for $($objUserInfo.SamAccountName)" | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                        }
                        else {
                            "'User cannot change password' already unchecked for $($objUserInfo.SamAccountName)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                        }

                        # If it's a new user, add SamAccountName and ExpiresDate to the txt file so the user is no more notified
                        if($NotifyNewUsers -and $objUserInfo.WithPolicyNoExpiration) {
                            $arrNewUsersContentToAdd += "$($objUserInfo.SamAccountName)|$($objUserInfo.ExpiresOn.ToString('dd.MM.yyyy HH:mm'))"

                            "'$($objUserInfo.SamAccountName)' will be added to '$strNewUsersNotifiedPath'" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                        }
                    }
                    else {
                        $strStatusNotification = 'NotNotified'
                        $objStatistics.TotalNotNotified += 1
                    }

# # #           Live Report           # # #

                    if($CreateLiveReport) {
                        $objReport += [PSCustomObject]@{
                            Name                  = $objUserInfo.Name
                            SamAccountName        = $objUserInfo.SamAccountName
                            Email                 = $objUserInfo.Email
                            PasswordNeverExpires  = $objUserInfo.PasswordNeverExpires
                            DaysBeforeExpire      = $objUserInfo.DaysBeforeExpire
                            DaysBeforeExpireRound = $objUserInfo.DaysBeforeExpireRound
                            ExpiresOn             = $objUserInfo.ExpiresOn
                            StatusNotification    = $strStatusNotification
                            Reason                = $strReason
                        }
                    }

                    $objStatistics.TotalChecked += 1

# # # # # # # # # # # # # # # # # # # # # #

                    if($MailQuotaMax -and ($objStatistics.TotalNotified -ge $MailQuotaMax)) {
                        'Mail quota reached' | Write-CMLogEntry -Severity 2 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                        break
                    }

                    $strReason = ''
                }

                # Add NewUsers notified to file
                if($arrNewUsersContentToAdd) {
                    Add-Content -Path $strNewUsersNotifiedPath -Value $arrNewUsersContentToAdd

                    "'$strNewUsersNotifiedPath' updated" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                }

                # Export live report if requested
                if($CreateLiveReport) {
                    $objReport | Export-Csv -Path $($objScriptInfo.ReportPath) -NoTypeInformation -Delimiter ';'

                    "Report exported to $($objScriptInfo.ReportPath)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
                }

                break
            }


# # #      Create AD State Report     # # #

            {$PSItem -eq 'REPORT'} {
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

                $objReport | Export-Csv -Path $objScriptInfo.ReportPath -NoTypeInformation -Delimiter ';'

                "Report exported to $($objScriptInfo.ReportPath)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

                break
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        "AD Group $($ADGroup) does not exist" | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    }
    catch {
        $_.Exception.Message | Write-CMLogEntry -Severity 3 -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    }
}
End {
    '#############################################################' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Invalid Email $(':'.PadLeft(9)) $($objStatistics.TotalEmailInvalid)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total New User $(':'.PadLeft(14)) $($objStatistics.TotalNewUser)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Not Expired $(':'.PadLeft(10)) $($objStatistics.TotalNotExpired)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

    if($ADGroup) {
        "Total Not on ADGroup $(':'.PadLeft(0)) $($objStatistics.TotalNotOnADGroup)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    }

    "Total Notified $(':'.PadLeft(16)) $($objStatistics.TotalNotified)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Not Notified $(':'.PadLeft(9)) $($objStatistics.TotalNotNotified)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "Total Checked $(':'.PadLeft(15)) $($objStatistics.TotalChecked)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    '#############################################################' | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

    [TimeSpan]$tsScriptTimeElapsed = New-TimeSpan -Start $dtScriptStart -End (Get-Date).ToLocalTime()
    "Script elapsed time : $("{0:hh}:{0:mm}:{0:ss}" -f $tsScriptTimeElapsed)" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt
    "[END] Execution of $($objScriptInfo.ScriptName).ps1" | Write-CMLogEntry -LogsDirectory $objScriptInfo.LogPath -FileName $objScriptInfo.LogFileName -LogIt $LogIt

    EXIT 0
}