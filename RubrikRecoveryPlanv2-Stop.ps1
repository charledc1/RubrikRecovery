########################################################################################################################
# Start of the script - Description, Requirements & Legal Disclaimer
########################################################################################################################
# Written by: Joshua Stenhouse joshuastenhouse@gmail.com
################################################
# Description:
# This script stops a Recovery Plan for VMs listed in the configured CSV
################################################ 
# Requirements:
# - Run PowerShell as administrator with command "Set-ExecutionPolcity unrestricted" on the host running the script
# - A Rubrik cluster or EDGE appliance, network access to it and credentials to login
# - A CSV with the following fields: VMName,Action,DisableNetwork,RemoveNetworkDevices,PowerOn,RunScriptsinLiveMount,PreFailoverScript,PostFailoverScriptDelay,PostFailoverScript,NextVMFailoverDelay,PreFailoverUserPrompt,PostFailoverUserPrompt
# - Example CSV Line = FileServer1,LiveMount,TRUE,FALSE,TRUE,FALSE,,0,,30,Are you bloody sure?,Has the VM come online?
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
# Configure the variables below for the Rubrik Cluster
################################################
$RubrikCluster = "192.168.1.201"
$RecoveryPlanCSV = "C:\RubrikRecoveryPlanv2\Advanced\RubrikRecoveryPlanA.csv"
$LogDirectory = "C:\RubrikRecoveryPlanv2\Advanced\Logs"
# Prompting for username and password to authenicate, can set manually to remove human interaction
$Credentials = Get-Credential -Message "Enter Rubrik login credentials"
$RubrikUser = $Credentials.UserName
$Credentials.Password | ConvertFrom-SecureString
$RubrikPassword = $Credentials.GetNetworkCredential().password
# Ensure the suffix matches the suffix specified in your run script otherwise it won't find any VMs to unmount!
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
$Log = $LogDirectory + "\Rubrik-RecoveryPlanStopLog-" + $Now.ToString("yyyy-MM-dd") + "@" + $Now.ToString("HH-mm-ss") + ".log"
Start-Transcript -Path $Log -NoClobber 
$RecoveryPlanVMs = import-csv $RecoveryPlanCSV
################################################
# Building Rubrik API string & invoking REST API
################################################
$BaseURL = "https://" + $RubrikCluster + "/api/v1/"
$RubrikSessionURL = $BaseURL + "session"
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RubrikUser+":"+$RubrikPassword))}
$Type = "application/json"
# Authenticating with API
Try 
{
$RubrikSessionResponse = Invoke-RestMethod -Uri $RubrikSessionURL -Headers $Header -Method POST -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Extracting the token from the JSON response
$RubrikSessionHeader = @{'Authorization' = "Bearer $($RubrikSessionResponse.token)"}
###############################################
# Getting list of VMs
###############################################
$VMListURL = $baseURL+"vmware/vm?limit=5000"
Try 
{
$VMListJSON = Invoke-RestMethod -Uri $VMListURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMList = $VMListJSON.data
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
###############################################
# Getting list of VM Live Mounts - For unmounting GET 
###############################################
$VMActiveLiveMountsURL = $baseURL+"vmware/vm/snapshot/mount"
Try 
{
$VMActiveLiveMountsJSON = Invoke-RestMethod -Uri $VMActiveLiveMountsURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMActiveLiveMounts = $VMActiveLiveMountsJSON.data
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
###################################################################
# Start Per VM  UnMount Action here
###################################################################
"Starting per VM RecoveryPlan Actions with VMSuffix:$VMSuffix"
foreach ($VM in $RecoveryPlanVMs)
{
###############################################
# Setting the variables for the current VM
###############################################
$VMName = $VM.VMName
# Setting VM live mount name
$VMLiveMountName = $VMName + $VMSuffix
# Selecting VM ID from live mount name
$VMID = $VMList | Where-Object {$_.name -eq $VMLiveMountName} | Select -ExpandProperty id -First 1
# Getting VM Live Mount ID
$VMLiveMountID = $VMActiveLiveMounts | Where-Object {$_.mountedVmId -eq $VMID} | Select -ExpandProperty id -First 1
# In case of a duplicate VM name in the vCenter the wrong VMID might be selected
# If $VMLiveMountID is $null checking against the 2nd VMID found
IF ($VMLiveMountID -eq $null)
{
$VMID = $VMList | Where-Object {$_.name -eq $VMLiveMountName} | Select -ExpandProperty id -First 1
$VMLiveMountID = $VMActiveLiveMounts | Where-Object {$_.vmId -eq $VMID} | Select -ExpandProperty id -First 1
}
###########################################
# Setting URL running DELETE to REST API
###########################################
$VMUnMountURL = $baseURL+"vmware/vm/snapshot/mount/"+$VMLiveMountID
###########################################
# POST to REST API URL with VMJSON
###########################################
# Only trying unmount if VMID found
IF ($VMLiveMountID -ne $null)
{
# Inserting space in log for readability
"--------------------------------------------"
"Performing UnMount for VM:$VMName"
# Giving the user 3 seconds to see
sleep 3
# DELETE request
Try 
{
Invoke-RestMethod -Method DELETE -Uri $VMUnMountURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMUnMountSuccess = $TRUE
}
Catch 
{
$VMUnMountSuccess = $FALSE
$_.Exception.ToString()
$error[0] | Format-List -Force
}
}
# End of per VM actions below
}
# End of per VM actions above
#
# Inserting space in log for readability
"UnMountSuccess:$VMUnMountSuccess"
"--------------------------------------------"
"End of RecoveryPlan Script"
################################################
# Stopping logging
################################################
Stop-Transcript
###############################################
# End of script
###############################################