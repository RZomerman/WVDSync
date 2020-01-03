#ReadGuestUsers
#ValidateArrayAgainstAD-GC-RemoveExisting
#RemoveAccountsFromADNotExisting
#CreateNewAccounts

Function WriteDebug{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$true)][string]$Value)
    Process{
        If ($Debug) {
        Write-host $Value
        }
    }
}

Function ActivateLogfile(){
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$true)][string]$LogFilePath)
    Add-Content -Path $LogFilePath -Value "***************************************************************************************************"
    Add-Content -Path $LogFilePath -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $LogFilePath -Value "***************************************************************************************************"
    Add-Content -Path $LogFilePath -Value ""
    Write-Host ("Logfile: " + $LogFilePath)
}


Function WriteLog{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][string]$Color
    )
    If (!($Color)) {$Color="white"}
    
        write-host $Value -ForegroundColor $color 
        Add-Content -Path $Path -Value $Value
    
}


Function RemoveUserFromApp ($RDSTenantName, $HostPoolName, $AppGroupName, $UserPrincipalName) {
    $void=Remove-RdsAppGroupUser -TenantName $RDSTenantName -HostPoolName $hostpoolName -AppGroupName $AppGroup1.AppGroupName -UserPrincipalName $UserPrincipalName
}


Function AddUserToApp ($RDSTenantName, $HostPoolName, $AppGroupName, $UserPrincipalName) {
    $void=Add-RdsAppGroupUser -TenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName -UserPrincipalName $UserPrincipalName
}

Function GetRDSAppMembers ($RDSTenantName, $HostPoolName, $AppGroupName) {
    [array]$WVDAppMembers=(Get-RdsAppGroupUser -TenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $AppGroupName).UserPrincipalName
    If (!($Members)) {
        return $false
    }else{
        return $WVDAppMembers
    }
}
Function GetAzureADGroupMembers ($AADGroupName){
    #Retrieves the members of an AAD group
    $AzureADGroup=Get-AzureADGroup | Where-Object DisplayName -eq $AADGroupName

    #Need to validate if the group if an AD Sync'd group, else WVD would not work for this group! - may be removed if AAD-DS implementation is in place
    If ( $AzureADGroup.DirSyncEnabled -ne "True") {
        Write-Host "Input group is not AD Sync enabled - remove this function from psm1 file if using AAD-DS"
        return $false
    }
    #End of statement that must be removed for AAD-DS implementations

    If (!($AzureADGroup)){
        return $false
    }else{
        [array]$GroupMembers=(Get-AzureADGroupMember -ObjectId $AzureADGroup.ObjectId).UserPrincipalName
        return $GroupMembers
    }
}
Function AZConnect {
    Connect-AzureAD 
    If (!(Get-AzureADCurrentSessionInfo)) {
        return $false
    }
    return $true
}


Function Add-CertificatePermission {
    param(
    [string]$userName,
    [string]$permission,
    [string]$certStoreLocation,
    [string]$certThumbprint
    );
    # check if certificate is already installed
    $certificateInstalled = Get-ChildItem cert:$certStoreLocation | Where thumbprint -eq $certThumbprint

    # download & install only if certificate is not already installed on machine
    if ($certificateInstalled -eq $null)
    {
        $message="Certificate with thumbprint:"+$certThumbprint+" does not exist at "+$certStoreLocation
        Write-Host $message -ForegroundColor Red
        return $false
    }else
    {
        try
        {
            $rule = new-object security.accesscontrol.filesystemaccessrule $userName, $permission, allow
            $root = "c:\programdata\microsoft\crypto\rsa\machinekeys"
            $l = ls Cert:$certStoreLocation
            $l = $l |? {$_.thumbprint -like $certThumbprint}
            $l |%{
                $keyname = $_.privatekey.cspkeycontainerinfo.uniquekeycontainername
                $p = [io.path]::combine($root, $keyname)
                if ([io.file]::exists($p))
                {
                    $acl = get-acl -path $p
                    $acl.addaccessrule($rule)
                    echo $p
                    set-acl $p $acl
                }
            }
        }
        catch 
        {
            Write-Host "Caught an exception:" -ForegroundColor Red
            Write-Host "$($_.Exception)" -ForegroundColor Red
            return $false
        }    
    }

    #exit $LASTEXITCODE
}

Function RDSConnect ($RDSTenantName, $HostPoolName, $AppGroupName) {
     Add-RdsAccount -DeploymentUrl "https://rdbroker.wvd.microsoft.com" 
     #Validate if tenant name and hostpool and app group actually exist, else return false and quit the script
     If (!(Get-RdsTenant).TenantName -contains $RDSTenantName) {
        Write-host "Tenant not found" -ForegroundColor "Red"
        return $false   
     }
     if (!(Get-RdsHostPool -TenantName $RDSTenantName).HostPoolName -contains $HostPoolName) {
        Write-host "Hostpool not found" -ForegroundColor "Red"
        return $false   
     }
     if (!(Get-RdsAppGroup -TenantName $RDSTenantName -HostPoolName $HostPoolName).AppGroupName -contains $AppGroupName) {
        Write-host "Application not found" -ForegroundColor "Red"
        return $false   
     }
     
     return $true
}


Function LoadModule {
    param (
        [parameter(Mandatory = $true)][string] $name
    )

    $retVal = $true
    if (!(Get-Module -Name $name))
    {
        $retVal = Get-Module -ListAvailable | where { $_.Name -eq $name }
        if ($retVal) {
            try {
                Import-Module $name -ErrorAction SilentlyContinue
            }
            catch {
                $retVal = $false
            }
        }
    }
    return $retVal
}

Function GeneratePassword2{
    Param (
        [int]$Length = 40
    )
    Add-Type -AssemblyName System.Web
    $CharSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{]+-[*=@:)}$^%;(_!&#?>/|.'.ToCharArray()
    #Index1s 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456
    #Index10s 0 1 2 3 4 5 6 7 8   
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($Length)
    $rng.GetBytes($bytes)
    $rawPass = New-Object char[]($Length)
    For ($i = 0 ; $i -lt $Length ; $i++){
        $rawPass[$i] = $CharSet[$bytes[$i]%$CharSet.Length]
    }
    $Return=(-join $rawPass)
    #WriteDebug -Value (-join $rawPass)
    Return ( $Return)
}

Function Validate-AADGroup ($Group) {
    $AzureADGroup=Get-AzureADGroup | Where-Object DisplayName -eq $Group
    If ($AzureADGroup) {
        return $true
    }else{
        return $false
    }
}

Function Start-RDSAADSync ($AADGroup, $RDSTenantName, $HostPoolName, $WVDAppGroup, $LogFilePathName) {


    $AADUsers=GetAzureADGroupMembers -AADGroupName $AADGroup
    $WVDAppUsers=GetRDSAppMembers -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup

    If (LogFilePathName) {
    WriteLog -Path $LogFilePathName -Value (" AAD WVD Users: " + $AADUsers.count) -color "Yellow"
    WriteLog -Path $LogFilePathName -Value (" WVD APP Users: " + $WVDAppUsers.count) -color "Yellow"
    }else{
        Write-host (" AAD WVD Users: " + $AADUsers.count) -Foregroundcolor "Yellow"
        Write-host (" WVD APP Users: " + $WVDAppUsers.count) -Foregroundcolor "Yellow"
    }
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
        If ($LogFilePathName) {
            WriteLog -Path $LogFilePathName -Value ("Full Delete of " + $WVDAppUsers.count + " wvd app users") -color "Yellow"
        }else {
            Write-Host ("Full Delete of " + $WVDAppUsers.count + " wvd app users") -Foregroundcolor "Yellow"
        }
        $usersToDelete = New-Object System.Collections.ArrayList
        ForEach ($UPN in $WVDAppUsers) {
            #RemoveUserFromWVDAPP
            RemoveUserFromApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UPN
        }
    }elseif ($AADUsers -and (!($WVDAppUsers))) {
        #AAD UPN's found, and no WVD UPN's, full create
        $Full=$true
        If ($LogFilePathName){
            WriteLog -Path $LogFilePathName -Value ("Full add of " + $AADUsers.count + " wvd app users") -color "Yellow"
        }else{
            Write-host ("Full add of " + $AADUsers.count + " wvd app users") -Foregroundcolor "Yellow" 
        }
        ForEach ($UPN in $WVDAppUsers) {
            #AddUserToWVDAPP 
            AddUserToApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UPN
        }
        
    }

    #ACTUAL Adding  & Removal OF ACCOUNTS 
    If ($usersToAdd) {
        If ($LogFilePathName){
            WriteLog -Path $LogFilePathName -Value ("Need to add " + $usersToAdd.count + " users")
        }else{
            Write-Host ("Need to add " + $usersToAdd.count + " users")
        }
        ForEach ($UserUPN in $usersToAdd) {
            If ($LogFilePathName){
                WriteLog -Path $LogFilePathName -Value (" adding " + $UserUPN.InputObject) -Color "Green"
            }else{
                Write-Host (" adding " + $UserUPN.InputObject) -ForegroundColor "Green"
            }
            #Get The original object from AADUsers array - to be able to extract all required info
            AddUserToApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UserUPN.InputObject

        Write-host "Next user" -ForegroundColor Green
        }
    }

    If ($usersToDelete) {
        If ($LogFilePathName){
            WriteLog -Path $LogFilePathName -Value ("Need to remove " + $usersToDelete.count + " users from WVD App")
        }else{
            Write-Host ("Need to remove " + $usersToDelete.count + " users from WVD App")
        }
        ForEach ($UserUPN in $usersToDelete) {
            If ($LogFilePathName) {
                WriteLog -Path $LogFilePathName -Value (" removing " + $UserUPN.InputObject) -Color "Yellow"
            }else{
                Write-Host (" removing " + $UserUPN.InputObject) -ForegroundColor "Yellow"
            }
            RemoveUserFromApp -RDSTenantName $RDSTenantName -HostPoolName $HostPoolName -AppGroupName $WVDAppGroup -UserPrincipalName $UserUPN.InputObject

        }
    }

    If (!($full) -and (!($usersToAdd)) -and (!($usersToDelete))) {
        If ($LogFilePathName) {
            WriteLog -Path $LogFilePathName -Value (" ** Fully synchronized ** " ) -Color "Green"
        }else{
            Write-Host (" ** Fully synchronized ** " ) -ForegroundColor "Green"
        }
    }
}
