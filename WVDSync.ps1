Param (
    [parameter()]
    $AADGroup,
    [parameter()]
    $HostPoolName,
    [parameter()]
    $WVDAppGroupName,
    [parameter()]
    $RDSTenantName,
    [parameter()]
    $Login,
    [parameter()]
    $Provision,
    [parameter()]
    $Automated,
    [parameter()]
    $ApplicationId
)  


<#

$AADGroup = AAD GROUP
$HostPoolName = HOSTPOOL 
$WVDAppGroupName = WVD App Group
$RDSTenantName  = RDSTenantname

WVDSync.ps1 -AADGroup "App1Users" -HostPoolName "Pool1" -WVDAppGroupName "Apps1" -RDSTenantName $RDSTenantName


.\WVDSync.ps1 -AADGroup CitrixUsers -HostPoolName $HostPoolName -WVDAppGroupName $AppGroupName -RDSTenantName $RDSTenantName -Login $true


#Workings: 
    <Optional>
        Connect AAD
        Connect RDS
    </optional>
    Read AAD Group
    Validate HostPool for App group
    If exist
        Read users on app group
        validate against AAD Users per UPN

    If no WVD but AAD - run Full ADD
    If no AAD but WVD - run Full Delete
    
    create difference groups
            AAD<<WVD (Remove)
            AAD>>WVD (Add)

    Run Add
    Run Remove


    !! NOTE !! AppProvisioning is not yet built - provision is an illegal parameter at the moment
#>


If ($ApplicationId) {
    $Automated = $true
}

#Cosmetic stuff
write-host ""
write-host ""
write-host "                               _____        __                                " -ForegroundColor Green
write-host "     /\                       |_   _|      / _|                               " -ForegroundColor Yellow
write-host "    /  \    _____   _ _ __ ___  | |  _ __ | |_ _ __ __ _   ___ ___  _ __ ___  " -ForegroundColor Red
write-host "   / /\ \  |_  / | | | '__/ _ \ | | | '_ \|  _| '__/ _' | / __/ _ \| '_ ' _ \ " -ForegroundColor Cyan
write-host "  / ____ \  / /| |_| | | |  __/_| |_| | | | | | | | (_| || (_| (_) | | | | | |" -ForegroundColor DarkCyan
write-host " /_/    \_\/___|\__,_|_|  \___|_____|_| |_|_| |_|  \__,_(_)___\___/|_| |_| |_|" -ForegroundColor Magenta
write-host "     "
write-host "This script reads the input groupname and validates / synchronizes WVD Membership" -ForegroundColor Green


#Importing the functions module and primary modules for AAD and AD
Import-Module .\WVDSync.psm1
If (!((LoadModule -name AzureAD))){
    Write-host "AzureAD Module was not found - cannot continue - please install the module with Install-Module AzureAD"
    Exit
}
If (!((LoadModule -name Microsoft.RDInfra.RDPowershell))){
    Write-host "Microsoft.RDInfra.RDPowershell Module was not found - cannot continue - please install the module install-module"
    Exit
}


#Generating and activating standard Log file
    $date=(Get-Date).ToString("d-M-y-h.m.s")
    $logname = ("WVD-" + $date + ".log")
    $workingDirectory=$PSScriptRoot
    #New-Item -Path $workingDirectory -Value $LogName -ItemType File
    $LogFilePathName=$workingDirectory + "\" + $LogName
    ActivateLogFile -LogFilePath $LogFilePathName


    #ProvisionAADServiceAccount
    #THIS NEEDS TO BE ADJUSTED TO ALLOW FOR MULTIPLE GROUPS TO BE ADDED TO THE SAME SCRIPT - PERHAPS A CONFIG FILE?
If ($Provision) {
    #CANNOT PROVISION THIS SCRIPT YET
    Write-host "ILLEGAL OPTION"
    Exit

    #Need to catch if powershell is open in admin mode (as script provisions Certificates in local machine and scheduled task)
    if (!([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))){
        Write-host "Please start powershell in admin mode for provisioning mode"
        exit
    }
    Write-Host "Login to Azure AD with Global Admin Account"
    If ($Login){Connect-AzureAD} 
    $tenant = Get-AzureADTenantDetail

    #Cleaning up existing certs
    $certold=Get-ChildItem cert:\localmachine\my | Where-Object {$_.Subject -eq 'CN=WVDSyncScript'} | Remove-Item

    #cleaning old application
    If ($ExistingApplication=Get-AzureADApplication |Where-Object {$_.DisplayName -eq 'WVDSyncScript'}) {
        WriteLog -Path $LogFilePathName -Value ("Existing application found - removing application")
        Remove-AzureADApplication -ObjectId $ExistingApplication.ObjectId
        Write-Host "Removed old application, need to pause for 10 seconds"
        sleep 10

    }

    #Cleaning Scheduled Tasks
    if (Get-ScheduledTask -TaskName 'AADtoWVDSync' -ErrorAction SilentlyContinue){
        Unregister-ScheduledTask -TaskName 'AADtoWVDSync' -Confirm:$false
    }

    # Create the self signed cert
    Write-Host "Generating Certificate"
    $currentDate = Get-Date
    $endDate  = $currentDate.AddYears(1)
    $notAfter  = $endDate.AddYears(1)
    $pwd  = GeneratePassword2
    $thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\localmachine\my -Subject "WVDSyncScript" -DnsName $tenant.ObjectId -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
    $pwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
    Export-PfxCertificate -cert "cert:\localmachine\my\$thumb" -FilePath ($workingDirectory + "\WVDCert.pfx") -Password $pwd

    # Load the certificate
    $cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate(($workingDirectory + "\WVDCert.pfx"), $pwd)
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())


    # Create the Azure Active Directory Application
    Write-Host "Creating Service Principle"
    $application = New-AzureADApplication -DisplayName "WVDSyncScript"
    

    New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier "WVDSyncScript" -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue

    # Create the Service Principal and connect it to the Application
    $sp = New-AzureADServicePrincipal -AppId $application.AppId -DisplayName WVDSyncScript

    # Give the Service Principal Reader access to the current tenant (Get-AzureADDirectoryRole)
    Write-host "Provining Read access to SP in AAD"
    $NewRole = $null
    $Retries = 0;
    write-host "waiting 15 for service principal to have finished creating"
    Sleep 15
    $DirectoryReaders=Get-AzureADDirectoryRole | where {$_.DisplayName -eq 'Directory Readers'}
    While ($NewRole -eq $null -and $Retries -le 6)
    {
        # Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
        Add-AzureADDirectoryRoleMember -ObjectId $DirectoryReaders.ObjectId -RefObjectId $sp.ObjectId | Write-Verbose -ErrorAction SilentlyContinue
        $NewRole = ((Get-AzureADDirectoryRoleMember -ObjectId $DirectoryReaders.ObjectId).objectID -contains $sp.ObjectId)
        $Retries++;
        write-host "waiting for SP to be added to group"                
        Sleep 15

     }
    

    # Get Tenant Detail

    # Now you can login to Azure PowerShell with your Service Principal and Certificate
    #Register a scheduled task
    Write-Host $application.AppId
    $AppID=$application.AppId
    $arguments=" -NoProfile -command & '$workingDirectory + \WVDSync.ps1' -ApplicationId $AppID"
    Write-host "Creating Scheduled Task with Arguments:"
    write-host $arguments


    

    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $arguments
    $trigger =  New-ScheduledTaskTrigger -Daily -At 3am
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AADtoWVDSync" -Description "Synchronizes WVD accounts daily to WVD"
}
#END OF AUTOMATED PROVISIONING 


#IF running automated, the stored certificate will be used to authenicate and get the AAD Tenant. The variable -ApplicationID is used for the Service Principal.
If ($Automated) {

        #CANNOT PROVISION THIS SCRIPT YET
        Write-host "ILLEGAL OPTION"
        Exit
    #If using service principal, need to login with SP
    
    If (!($ApplicationId)){
        Write-host "No ApplicationID found - exit"
        Exit
    }
    $cert=Get-ChildItem cert:\localmachine\my | where {$_.Subject -eq 'CN=WVDSyncScript'}
    $thumb = $cert.Thumbprint
    $tenantObjectID=$cert.DnsNameList.unicode
    Connect-AzureAD -TenantId $tenantObjectID -ApplicationId $ApplicationId -CertificateThumbprint $thumb
    $login=$false
}


#ActualStartOfScript
#Creating the two arrays to be used


$AADUPN = New-Object System.Collections.ArrayList
$WVDUPN = New-Object System.Collections.ArrayList

If ($Login) {
    Write-host "The script will ask you for 2x Login" -ForegroundColor "Yellow"
    Write-host "The first login will be the Azure AD Login - can be AD Reader - no need for admin privileges"  -ForegroundColor "Yellow"
    Write-host "The second login will be the WVD/RDS Admin Login"  -ForegroundColor "Yellow"
    Write-host "You can also specify -Login $false and login manually prior to running the script"
    write-host "            ...Press any key to continue..."  -ForegroundColor CYAN
    [void][System.Console]::ReadKey($true)
    If (!(AZConnect)) {
        WriteLog -Path $LogFilePathName -Value ("FATAL AD ERROR - EXIT") -color "Red"
        exit    
    }

    If (!(RDSConnect -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup)) {
        WriteLog -Path $LogFilePathName -Value ("FATAL WVD ERROR - EXIT") -color "Red"
        exit
    }

}

#Login to the local AD - and retrieve the users from the specified OU - based on GC (to make the query faster)
#Next retrieve all B2B / guest users from AAD

$AADUsers=GetAzureADGroupMembers -AADGroupName $AADGroup
$WVDAppUsers=GetRDSAppMembers -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup

WriteLog -Path $LogFilePathName -Value (" AAD WVD Users: " + $AADUsers.count) -color "Yellow"
WriteLog -Path $LogFilePathName -Value (" WVD APP Users: " + $WVDAppUsers.count) -color "Yellow"

Write-host ""
#As one of the two arrays could be empty, we also need to add workarounds in case that is so.. 
#The result of this part is two new arrays (or one depending on scenario) with objects: object.InputObject  == UPN
If ($WVDAppUsers -and $AADUsers){
    [array]$UserSyncStatus = Compare-Object -ReferenceObject ($WVDAppUsers) -DifferenceObject ($AADUsers)
    [array]$usersToDelete=$UserSyncStatus | where {$_.SideIndicator -eq '<='}
    [array]$usersToAdd=$UserSyncStatus | where {$_.SideIndicator -eq '=>'}
}elseif ($WVDAppUsers -and (!($AADUsers))) {
    #WVD UPN's found, no AAD UPN's full delete
    $Full=$true
    WriteLog -Path $LogFilePathName -Value ("Full Delete of " + $WVDAppUsers.count + " wvd app users") -color "Yellow"
    $usersToDelete = New-Object System.Collections.ArrayList
    ForEach ($UPN in $WVDAppUsers) {
        #RemoveUserFromWVDAPP
        RemoveUserFromApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UPN
    }
}elseif ($AADUsers -and (!($WVDAppUsers))) {
    #AAD UPN's found, and no WVD UPN's, full create
    $Full=$true
    WriteLog -Path $LogFilePathName -Value ("Full add of " + $AADUsers.count + " wvd app users") -color "Yellow"
    ForEach ($UPN in $WVDAppUsers) {
        #AddUserToWVDAPP 
        AddUserToApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UPN
    }
       
}

#ACTUAL Adding  & Removal OF ACCOUNTS 
If ($usersToAdd) {
    WriteLog -Path $LogFilePathName -Value ("Need to add " + $usersToAdd.count + " users")
    ForEach ($UserUPN in $usersToAdd) {
        WriteLog -Path $LogFilePathName -Value (" adding " + $UserUPN.InputObject) -Color "Green"
        #Get The original object from AADUsers array - to be able to extract all required info
        AddUserToApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UserUPN.InputObject

    Write-host "Next user" -ForegroundColor Green
    }
}

If ($usersToDelete) {
    WriteLog -Path $LogFilePathName -Value ("Need to remove " + $usersToDelete.count + " users from WVD App")
    ForEach ($UserUPN in $usersToDelete) {
        WriteLog -Path $LogFilePathName -Value (" removing " + $UserUPN.InputObject) -Color "Yellow"
        RemoveUserFromApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UserUPN.InputObject

    }
}

If (!($full) -and (!($usersToAdd)) -and (!($usersToDelete))) {
    WriteLog -Path $LogFilePathName -Value (" ** Fully synchronized ** " ) -Color "Green"
}
write-host ""
write-host ""
write-host ""

