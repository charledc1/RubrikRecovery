########################################################################################################################
# Start of the script - Description, Requirements & Legal Disclaimer
########################################################################################################################
# Written by: Joshua Stenhouse joshuastenhouse@gmail.com
################################################
# Description:
# This reconfigures the VMs listed in the Recovery Plan CSV against a vSphere 6.5 vCenter
################################################ 
# Requirements:
# - Run PowerShell as administrator with command "Set-ExecutionPolcity unrestricted" on the host running the script
# - A VMware vCenter 6.5 server, required as this script leverages the REST APIs in 6.5 onwards
# - A CSV with the following fields: VMName,HostSelection,DisableNetwork,RemoveNetworkDevices,RubrikPowerOn,RunScriptsinLiveMount,PreFailoverScript,PostFailoverScriptDelay,PostFailoverScript,NextVMFailoverDelay,PreFailoverUserPrompt,PostFailoverUserPrompt,vCenterPowerOn,ConfigureNIC,PortGroup,ConnectNIC
# - Example CSV Line = DemoApp1-VM01,192.168.1.14,FALSE,FALSE,FALSE,FALSE,,0,,0,,,TRUE,TRUE,Isolated,TRUE
################################################
# Legal Disclaimer:
# This script is written by Joshua Stenhouse is not supported under any support program or service. 
# All scripts are provided AS IS without warranty of any kind. 
# The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever 
# (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, even if the author has been advised of the possibility of such damages.
################################################
# Configure the variables below for the vCenter
################################################
$vCenterServer = "192.168.1.10"
$RecoveryPlanCSV = "C:\RubrikRecoveryPlanv2\Advanced\RubrikRecoveryPlanA.csv"
$LogDirectory = "C:\RubrikRecoveryPlanv2\Advanced\Logs"
# Prompting for username and password to authenicate, can set manually to remove human interaction
$Credentials = Get-Credential -Message "Enter vCenter login credentials"
$vCenterUser = $Credentials.UserName
$Credentials.Password | ConvertFrom-SecureString
$vCenterPassword = $Credentials.GetNetworkCredential().password
# Ensure the suffix matches the suffix specified in your run script otherwise it won't find any VMs to configure!
$VMSuffix = " - Live Mount"
########################################################################################################################
# Nothing to configure below this line - Starting the main function of the script
########################################################################################################################
# Adding certificate exception to prevent API errors
################################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
################################################
# Starting logging & importing the CSV
################################################
$Now = get-date
$Log = $LogDirectory + "\Rubrik-RecoveryPlanConfigureLog-" + $Now.ToString("yyyy-MM-dd") + "@" + $Now.ToString("HH-mm-ss") + ".log"
Start-Transcript -Path $Log -NoClobber 
$RecoveryPlanVMs = import-csv $RecoveryPlanCSV
################################################
# Building vCenter API string & invoking REST API
################################################
$BaseAuthURL = "https://" + $vCenterServer + "/rest/com/vmware/cis/"
$BaseURL = "https://" + $vCenterServer + "/rest/vcenter/"
$vCenterSessionURL = $BaseAuthURL + "session"
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($vCenterUser+":"+$vCenterPassword))}
$Type = "application/json"
# Authenticating with API
Try 
{
$vCenterSessionResponse = Invoke-RestMethod -Uri $vCenterSessionURL -Headers $Header -Method POST -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Extracting the session ID from the response
$vCenterSessionHeader = @{'vmware-api-session-id' = $vCenterSessionResponse.value}
###############################################
# Getting list of VMs
###############################################
$VMListURL = $BaseURL+"vm"
Try 
{
$VMListJSON = Invoke-RestMethod -Method Get -Uri $VMListURL -TimeoutSec 100 -Headers $vCenterSessionHeader -ContentType $Type
$VMList = $VMListJSON.value
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
###############################################
# Getting list of Port Groups
###############################################
$PortGroupListURL = $BaseURL+"network"
Try 
{
$PortGroupListJSON = Invoke-RestMethod -Method Get -Uri $PortGroupListURL -TimeoutSec 100 -Headers $vCenterSessionHeader -ContentType $Type
$PortGroupList = $PortGroupListJSON.value
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
###################################################################
# Start Per VM Configure Action here
###################################################################
"Starting per VM RecoveryPlan Actions with VMSuffix:$VMSuffix"
foreach ($VM in $RecoveryPlanVMs)
{
###############################################
# Setting the variables for the current VM
###############################################
$VMName = $VM.VMName
$VMDisableNetwork = $VM.DisableNetwork
$VMRubrikPowerOn = $VM.RubrikPowerOn
$VMPostFailoverScriptDelay = $VM.PostFailoverScriptDelay
$VMNextVMFailoverDelay = $VM.NextVMFailoverDelay
$VMvCenterPowerOn = $VM.vCenterPowerOn
$VMConfigureNIC = $VM.ConfigureNIC
$VMConnectNIC = $VM.ConnectNIC
$VMPortGroup = $VM.PortGroup
# Setting VM live mount name
$VMLiveMountName = $VMName + $VMSuffix
# Inserting space in log for readability
"--------------------------------------------"
"Configuring VM:$VMLiveMountName"
###############################################
# Getting the VM ID from the vCenter VM list
###############################################
$VMID = $VMList | Where-Object {$_.name -eq $VMLiveMountName} | Select -ExpandProperty vm -First 1
IF ($VMID -eq $null)
{
"No VMID found for VM:$VMLiveMountName"
}
ELSE
{
###############################################
# Getting NICs to configure for the VM if set to reconfigure
###############################################
IF ($VMConfigureNIC -eq "TRUE")
{
$VMNICListURL = $BaseURL+"vm/"+$VMID+"/hardware/ethernet"
Try 
{
$VMNICListJSON = Invoke-RestMethod -Method Get -Uri $VMNICListURL -TimeoutSec 100 -Headers $vCenterSessionHeader -ContentType $Type
$VMNICList = $VMNICListJSON.value
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
$VMNICListCount = $VMNICList.count
# Inserting in log for readability
"Configuring $VMNICListCount NICs to PortGroup:$VMPortGroup"
###############################################
# Performing For Each VM NIC Action
###############################################
ForEach ($VMNIC in $VMNICList)
{
# Setting NIC ID
$VMNICID = $VMNIC.nic
# Building NIC URL
$VMNICURL = $BaseURL+"vm/"+$VMID+"/hardware/ethernet/"+$VMNICID 
# Selecting Port Group ID
$VMPortGroupID = $PortGroupList | Where-Object {$_.name -eq $VMPortGroup} | Select -ExpandProperty network
# Selecting Port Group Type (needed for vCenter API)
$VMPortGroupType = $PortGroupList | Where-Object {$_.name -eq $VMPortGroup} | Select -ExpandProperty type
# Building JSON
$VMNICJSON =
"{
  ""spec"":{
  ""backing"":{
    ""type"": ""$VMPortGroupType"",
    ""network"": ""$VMPortGroupID""
              }
           }
 }"
# Patching NIC with new settings
Try 
{
Invoke-RestMethod -Method Patch -Uri $VMNICURL -TimeoutSec 100 -Headers $vCenterSessionHeader -Body $VMNICJSON -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
"Will show error if Port Group is not on the ESXi host of the VM"
}
# Waiting 3 seconds for operation to complete
sleep 3
# Connecting NIC if specified and not already connected by Rubrik (to remove error if already connected)
IF (($VMConnectNIC -eq "TRUE") -And ($VMDisableNetwork -eq "TRUE"))
{
# Building NIC URL
$VMConnectNICURL = $BaseURL+"vm/"+$VMID+"/hardware/ethernet/"+$VMNICID+"/connect"
Try 
{
Invoke-RestMethod -Method POST -Uri $VMConnectNICURL -TimeoutSec 100 -Headers $vCenterSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
"Will error if the VM nic is already connected"
}
# Waiting 3 seconds for operation to complete
sleep 3
#
}
# End of Per NIC actions below
}
# End of Per NIC actions above
# End of IF VMConfigureNIC -eq TRUE below
}
# End of IF VMConfigureNIC -eq TRUE above
###############################################
# Powering On VM if VMvCenterPowerOn TRUE
###############################################
IF ($VMvCenterPowerOn -eq "TRUE")
{
$VMPowerOnURL = $BaseURL+"vm/"+$VMID+"/power/start"
# Output to host
"Powering On VM:$VMName" 
# Performing POST
Try 
{
Invoke-RestMethod -Method Post -Uri $VMPowerOnURL -TimeoutSec 100 -Headers $vCenterSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
###########################################
# Waiting for VMNextVMFailoverDelay if VMvCenterPowerOn TRUE
###########################################
"Sleeping $VMNextVMFailoverDelay seconds for VMNextVMFailoverDelay"
sleep $VMNextVMFailoverDelay
}
# Inserting space in log for readability
"End Of Operations For VM:$VMLiveMountName"
# Giving the user 3 seconds to see
sleep 3
# End of IF VMID not null below
}
# End of IF VMID not null above
#
# End of per VM actions below
}
# End of per VM actions above
#
# Inserting space in log for readability
"End of RecoveryPlan Script"
"--------------------------------------------"
################################################
# Stopping logging
################################################
Stop-Transcript
###############################################
# End of script
###############################################