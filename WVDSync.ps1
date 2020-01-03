
Param (
    [parameter()]
    $AADGroup,
    [parameter()]
    $HostPoolName,
    [parameter()]
    $AppGroupName,
    [parameter()]
    $TenantName,
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

WVDSync.ps1 -AADGroup "App1Users" -HostPoolName "Pool1" -AppGroupName "Apps1" -TenantName $TenantName


.\WVDSync.ps1 -AADGroup CitrixUsers -HostPoolName $HostPoolName -AppGroupName $AppGroupName -TenantName $TenantName -Login $true


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



$DesktopApplicationGroup="WVDDesktopUsers"

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
    #Write-host "ILLEGAL OPTION"
    #Exit

    #Need to catch if powershell is open in admin mode (as script provisions Certificates in local machine and scheduled task)
    if (!([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))){
        Write-host "Please start powershell in admin mode for provisioning mode"
        exit
    }

    If ($Login){
        Write-host "The script will ask you for 2x Login" -ForegroundColor "Yellow"
        Write-host "The first login will be the Azure AD Login must have admin privileges"  -ForegroundColor "Yellow"
        Write-host "The second login will be the WVD/RDS Admin Login"  -ForegroundColor "Yellow"
        Write-host "You can also specify -Login $false and login manually prior to running the script"
        write-host "            ...Press any key to continue..."  -ForegroundColor CYAN
        [void][System.Console]::ReadKey($true)
        If (!(AZConnect)) {
            WriteLog -Path $LogFilePathName -Value ("FATAL AD ERROR - EXIT") -color "Red"
            exit    
        }
    
        Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com" 
        If (!($RDSContext.TenantGroupName)) {
            Write-HOST "ERROR LOGGING INTO RDS OR NO TENANT FOUND" -ForegroundColor "Red"
        }
        Write-host ("Tenant Group:" + $RDSContext.TenantGroupName)

        }
    $tenant = Get-AzureADTenantDetail

    #Cleaning up existing certs
    $certold=Get-ChildItem cert:\localmachine\my | Where-Object {$_.Subject -eq 'CN=WVDSyncScript'} | Remove-Item

    #cleaning old application
    If ([array]$ExistingApplication=Get-AzureADApplication |Where-Object {$_.DisplayName -eq 'WVDSyncScript'}) {
        WriteLog -Path $LogFilePathName -Value ("Existing application found - removing application")
        ForEach ($app in $ExistingApplication) {
            Remove-AzureADApplication -ObjectId $app.ObjectId
        }
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

    Write-host "Provining Admin access to SP in RDS"
    $NewRDSRole = $null
    $Retries = 0;
    While ($NewRDSRole -eq $null -and $Retries -le 6) {
        [Array]$AllTenants=Get-RdsTenant
        If (!($AllTenants)){
            WriteLog -Path $LogFilePathName -Value ("FATAL ERROR - No tenants found - EXIT") -color "Red" 
            exit
        }else{
            ForEach ($Tenant in $AllTenants) {
                $AppID=$application.AppId
                $TenantName=$Tenant.TenantName

                WriteLog -Path $LogFilePathName -Value ("Adding AppID $AppId to tenant $TenantName") -color "Yellow" 
                
                New-RdsRoleAssignment -RoleDefinitionName "RDS Owner" -ApplicationId $application.AppId -TenantName $Tenant.TenantName    
                $NewRDSRole =  ((Get-RdsRoleAssignment -TenantName  $Tenant.TenantName ).appId -contains $application.AppId)
                $Retries++;
                write-host "waiting for SP to be added to RDS group"                
                Sleep 15
                #Just need to sleep to provide backend to catch-up
            }
        }
        
        
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
    #Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AADtoWVDSync" -Description "Synchronizes WVD accounts daily to WVD"
    exit
}
#END OF AUTOMATED PROVISIONING 

If ($Login -and (!($Automated))) {
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

    $RDSContext=Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com" 
    If (!($RDSContext.TenantGroupName)) {
        Write-HOST "ERROR LOGGING INTO RDS OR NO TENANT FOUND" -ForegroundColor "Red"
    }
    Write-host ("Tenant Group:" + $RDSContext.TenantGroupName)

    }




#IF running automated, the stored certificate will be used to authenicate and get the AAD Tenant. The variable -ApplicationID is used for the Service Principal.
If ($Automated) {

        #CANNOT PROVISION THIS SCRIPT YET
        #Write-host "ILLEGAL OPTION"
        #Exit
    #If using service principal, need to login with SP
    
    If (!($ApplicationId)){
        Write-host "No ApplicationID found - exit"
        Exit
    }
    $cert=Get-ChildItem cert:\localmachine\my | where {$_.Subject -eq 'CN=WVDSyncScript'}
    $thumb = $cert.Thumbprint
    $tenantObjectID=$cert.DnsNameList.unicode 
    Connect-AzureAD -TenantId $tenantObjectID -ApplicationId $ApplicationId -CertificateThumbprint $thumb
    $RDSContext=Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com" -ApplicationId  $ApplicationId -CertificateThumbprint $thumb -AadTenantId $tenantObjectID
    If (!($RDSContext)) {
        WriteLog -Path $LogFilePathName -Value ("ERROR LOGING IN AS APP ID") -color "Red" 
        exit
    }
    Write-host ("Tenant Group:" + $RDSContext.TenantGroupName)
    


    #Running Sequence
    [array]$AllTenants=Get-RdsTenant
    If (!($AllTenants)) {
        WriteLog -Path $LogFilePathName -Value ("ERROR RETRIEVING TENANTS") -color "Red" 
        exit
    }else{
        $TenantCount=$AllTenants.count
        $ti=0
        Foreach ($tenant in $AllTenants) {
            $ti++
            $TenantName=$tenant.TenantName
            WriteLog -Path $LogFilePathName -Value ("Retrieving Hostpools in tenant $ti of $TenantCount : $TenantName") -color "DarkCyan" 
         
            [array]$AllHostGroups=Get-RdsHostPool -TenantName $tenant.TenantName
            If (!($AllHostGroups)) {
                WriteLog -Path $LogFilePathName -Value ("ERROR RETRIEVING HOSTGROUPS in Tenant $TenantName") -color "Red" 
            }else{
                $hi=0
                $HostPoolCount=$AllHostGroups.count
                ForEach ($HostGroup in $AllHostGroups) {
                    $hi++
                    $HostPoolName=$HostGroup.HostPoolName
                    WriteLog -Path $LogFilePathName -Value ("Retrieving ApplicationGroups in hostpool $hi of $HostPoolCount : $HostPoolName") -color "Cyan" 
                    $allAppGroups=Get-RdsAppGroup -TenantName $tenant.TenantName -HostPoolName $HostGroup.HostPoolName
                    If (!($allAppGroups)) {
                        $HostGroup=$HostGroup.HostPoolName
                        WriteLog -Path $LogFilePathName -Value ("ERROR RETRIEVING Apps in $hostGroup") -color "Red" 
                    }else{
                        $ai=0
                        $AppGroupCount=$allAppGroups.count
                        #Per application, retrieve the description field and use that to request the sync
                        ForEach ($appGroup in $allAppGroups) {
                            $ai++
                            $AppGroupName=$appGroup.AppGroupName
                            WriteLog -Path $LogFilePathName -Value ("Retrieving Description of Application Group $ai of $AppGroupCount : $AppGroupName") -color "Gray" 
                            $AADGroup=$null
                            $AADGroup=$appGroup.Description
                            If (!($AADGroup)) {
                                WriteLog -Path $LogFilePathName -Value ("Application $AppGroupName does not have a description") -color "Yellow" 
                                continue
                            }else{
                                If ($AADGroup -eq 'The default desktop application group for the session host pool'){$AADGroup=$DesktopApplicationGroup}    
                                WriteLog -Path $LogFilePathName -Value ("  -validating AAD Group: $AADGroup ") -color "Yellow" 
                                If (Validate-AADGroup -Group $AADGroup) {
                                    
                                
                                    #Reset the arrays
                                    $AADUsers=$null
                                    $WVDAppUsers=$null

                                    $AADUsers=GetAzureADGroupMembers -AADGroupName $AADGroup
                                    [array]$WVDAppUsers=(Get-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName).UserPrincipalName
                                    
                                
                                    If ($LogFilePathName) {
                                    WriteLog -Path $LogFilePathName -Value ("    AAD WVD Users: " + $AADUsers.count) -color "Yellow"
                                    WriteLog -Path $LogFilePathName -Value ("    WVD APP Users: " + $WVDAppUsers.count) -color "Yellow"
                                    }else{
                                        Write-host (" AAD WVD Users: " + $AADUsers.count) -Foregroundcolor "Yellow"
                                        Write-host (" WVD APP Users: " + $WVDAppUsers.count) -Foregroundcolor "Yellow"
                                    }
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
                                            #RemoveUserFromApp -RDSTenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
                                            Remove-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
                                        }
                                    }elseif ($AADUsers -and (!($WVDAppUsers))) {
                                        #AAD UPN's found, and no WVD UPN's, full add
                                        $Full=$true
                                            WriteLog -Path $LogFilePathName -Value ("Full add of " + $AADUsers.count + " wvd app users") -color "Yellow"
                                            ForEach ($UPN in $AADUsers) {
                                                #AddUserToWVDAPP 
                                                #AddUserToApp -RDSTenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
                                                WriteLog -Path $LogFilePathName -Value (" adding " + $UPN) -Color "Green"
                                                Add-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
                                            }
                                        }

                                        #ACTUAL Adding  & Removal OF ACCOUNTS 
                                    If ($usersToAdd) {
                                        WriteLog -Path $LogFilePathName -Value ("Need to add " + $usersToAdd.count + " users")
                                        ForEach ($UserUPN in $usersToAdd) {
                                            WriteLog -Path $LogFilePathName -Value (" adding " + $UserUPN.InputObject) -Color "Green"
                                            #Get The original object from AADUsers array - to be able to extract all required info
                                            Add-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UserUPN.InputObject
                                            Write-host "Next user" -ForegroundColor Green
                                        }
                                    }

                                    If ($usersToDelete) {
                                        WriteLog -Path $LogFilePathName -Value ("Need to remove " + $usersToDelete.count + " users from WVD App")
                                        ForEach ($UserUPN in $usersToDelete) {
                                            WriteLog -Path $LogFilePathName -Value (" removing " + $UserUPN.InputObject) -Color "Yellow"
                                            #RemoveUserFromApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UserUPN.InputObject
                                            Remove-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UserUPN.InputObject

                                        }
                                    }
                                        If (!($full) -and (!($usersToAdd)) -and (!($usersToDelete))) {
                                            WriteLog -Path $LogFilePathName -Value (" ** $AppGroupName Fully Synchronized ** " ) -Color "Green"
                                        }
                              
                                    
                                    }else{
                                        WriteLog -Path $LogFilePathName -Value ("Azure AD Group $AADGroup for $AppGroupName not found " ) -Color "Red"
                                    }

                                }
                                

                            write-host ""
                            }                      
                        }
                    }
                }
            }
        }
}else{
    #ManualRunWithManualInput
    #AS Functions do not work with $AppLogins (Add-RDSConext errors occur on non-interactive logins), we have to repeat all of the above :( 
    #Reset the arrays

    $AADUsers=$null
    $WVDAppUsers=$null



    $AADUsers=GetAzureADGroupMembers -AADGroupName $AADGroup
    [array]$WVDAppUsers=(Get-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName).UserPrincipalName
    

    If ($LogFilePathName) {
    WriteLog -Path $LogFilePathName -Value ("    AAD WVD Users: " + $AADUsers.count) -color "Yellow"
    WriteLog -Path $LogFilePathName -Value ("    WVD APP Users: " + $WVDAppUsers.count) -color "Yellow"
    }else{
        Write-host (" AAD WVD Users: " + $AADUsers.count) -Foregroundcolor "Yellow"
        Write-host (" WVD APP Users: " + $WVDAppUsers.count) -Foregroundcolor "Yellow"
    }
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
            #RemoveUserFromApp -RDSTenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
            Remove-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
        }
    }elseif ($AADUsers -and (!($WVDAppUsers))) {
        #AAD UPN's found, and no WVD UPN's, full add
        $Full=$true
            WriteLog -Path $LogFilePathName -Value ("Full add of " + $AADUsers.count + " wvd app users") -color "Yellow"
            ForEach ($UPN in $AADUsers) {
                #AddUserToWVDAPP 
                #AddUserToApp -RDSTenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
                WriteLog -Path $LogFilePathName -Value (" adding " + $UPN) -Color "Green"
                Add-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UPN
            }
        }

        #ACTUAL Adding  & Removal OF ACCOUNTS 
    If ($usersToAdd) {
        WriteLog -Path $LogFilePathName -Value ("Need to add " + $usersToAdd.count + " users")
        ForEach ($UserUPN in $usersToAdd) {
            WriteLog -Path $LogFilePathName -Value (" adding " + $UserUPN.InputObject) -Color "Green"
            #Get The original object from AADUsers array - to be able to extract all required info
            Add-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UserUPN.InputObject
            Write-host "Next user" -ForegroundColor Green
        }
    }

    If ($usersToDelete) {
        WriteLog -Path $LogFilePathName -Value ("Need to remove " + $usersToDelete.count + " users from WVD App")
        ForEach ($UserUPN in $usersToDelete) {
            WriteLog -Path $LogFilePathName -Value (" removing " + $UserUPN.InputObject) -Color "Yellow"
            #RemoveUserFromApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UserUPN.InputObject
            Remove-RdsAppGroupUser -TenantName $TenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UserUPN.InputObject

        }
    }
        If (!($full) -and (!($usersToAdd)) -and (!($usersToDelete))) {
            WriteLog -Path $LogFilePathName -Value (" ** $AppGroupName Fully Synchronized ** " ) -Color "Green"
        }

    



}




#ActualStartOfScript
#Creating the two arrays to be used





#Login to the local AD - and retrieve the users from the specified OU - based on GC (to make the query faster)
#Next retrieve all B2B / guest users from AAD

write-host ""
write-host ""
write-host ""

