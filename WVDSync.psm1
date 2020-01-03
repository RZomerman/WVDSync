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

Function RDSConnect ($RDSTenantName, $HostPoolName, $AppGroupName) {
     Add-RdsAccount -DeploymentUr "https://rdbroker.wvd.microsoft.com" 
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


