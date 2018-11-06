########################################################################################################################
# Start of the script - Description, Requirements & Legal Disclaimer
########################################################################################################################
################################################
# Description:
# This script automatically exports the VMs specified in a CSV from Rubrik to the specified vCenter ESXi host and datastore.
# WARNING: All VMs exported by Rubrik are thick (lazy zeroed) VMDKs. Be careful on the space utilization of your storage 
################################################ 
# Requirements:
# - Run PowerShell as administrator with command "Set-ExecutionPolcity unrestricted" on the host running the script
# - A Rubrik cluster or EDGE appliance with login credentials that have permission to manage the backups for the VMs sepecified
# - A CSV with the following fields: SourceVMName,NewVMName,ESXiHost,Datastore
# - Example CSV Line = DemoApp1-VM01,DemoApp2-VM01,192.168.1.17,DC1SANVolume1
# - Each VM specified must be protected by Rubrik, otherwise there is nothing to export!
# - The ESXi hostname should match as it appears in the vCenter, in my example they are added by IP address
# - This script always uses the latest snapshot available
################################################
# Legal Disclaimer:
# This script is not supported under any support program or service. 
# All scripts are provided AS IS without warranty of any kind. 
# The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever 
# (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, even if the author has been advised of the possibility of such damages.
################################################
# Configure the variables below for the Rubrik Cluster
################################################
# Script files
$VMExportListCSV = "C:\Rubrik\RubrikExporter\VMExportList.csv"
# Rubrik settings
$RubrikCluster = "10.254.215.173"
$Credentials = IMPORT-CLIXML "C:\Rubrik\RubrikExporter\SecureCredentials.xml"
$RubrikUser = $Credentials.UserName
$RubrikPassword = $Credentials.GetNetworkCredential().Password
# Time delay between VM export requests, in seconds, default 300/5 minutes
$VMExportTimeDelay = 5
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
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
################################################
# Importing the CSV
################################################
$VMExportList = import-csv $VMExportListCSV
################################################
# Building Rubrik API string & invoking REST API
################################################
$BaseURL = "https://" + $RubrikCluster + "/api/v1/"
$RubrikSessionURL = $BaseURL + "session"
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RubrikUser+":"+$RubrikPassword))}
$Type = "application/json"
# Authentication with API
Try 
{
$RubrikSessionResponse = Invoke-WebRequest -Uri $RubrikSessionURL -Headers $Header -Method POST -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Extracting the token from the JSON response
$RubrikSession = (ConvertFrom-Json -InputObject $RubrikSessionResponse.Content)
$RubrikSessionHeader = @{'Authorization' = "Bearer $($RubrikSession.token)"}
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
###################################################################
# Start Per VM Actions here
###################################################################
"Starting per VM Actions"
foreach ($VM in $VMExportList)
{
  ###############################################
  # Setting the variables for the current VM and getting list of databases
  ###############################################
  $SourceVMName = $VM.SourceVMName
  $NewVMName = $VM.NewVMName
  $ESXiHost = $VM.ESXiHost
  $Datastore = $VM.Datastore
  ###############################################
  # Getting VM ID 
  ###############################################
  $VMID = $VMList | Where-Object {($_.name -eq $SourceVMName)} | select -ExpandProperty id
  ###############################################
  # Getting VM snapshot ID
  ###############################################
  $VMSnapshotURL = $baseURL+"vmware/vm/"+$VMID+"/snapshot"
  Try 
  {
    $VMSnapshotJSON = Invoke-RestMethod -Uri $VMSnapshotURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type 
    $VMSnapshot = $VMSnapshotJSON.data
  }
  Catch 
  {
    $_.Exception.ToString()
    $error[0] | Format-List -Force
  }
  # Selecting most recent VM snapshot to use for recovery operation
  $VMSnapshotID = $VMSnapshot | Sort-Object -Descending date | select -ExpandProperty id -First 1
  $VMSnapshotDate = $VMSnapshot | Sort-Object -Descending date | select -ExpandProperty date -First 1
  ###############################################
  # Getting ESXi Host ID
  ###############################################
  $ESXiHostsURL = $baseURL+"vmware/host"
  Try 
  {
    $ESXiHostsJSON = Invoke-RestMethod -Uri $ESXiHostsURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type 
    $ESXiHosts = $ESXiHostsJSON.data
  }
  Catch 
  {
    $_.Exception.ToString()
    $error[0] | Format-List -Force
  }
  # Selecting HostInfo and Host ID
  $ESXiHostInfo = $ESXiHosts | Where {$_.name -eq "$ESXiHost"}
  $ESXiHostID = $ESXiHostInfo.id
  ###############################################
  # Getting Datastore ID  -  Needed for other script.
  ###############################################
  $ESXiHostDatastores = $ESXiHostInfo.datastores
  $ESXiHostDatastoreID = $ESXiHostDatastores | Where {$_.name -eq "$Datastore"} | Select -ExpandProperty id
  ###############################################
  # Performing Export 
  ###############################################
  ###########################################
  # Setting URL, VM export recovery Name and creating JSON
  ###########################################
  $VMExportURL = $baseURL+"vmware/vm/snapshot/"+$VMSnapshotID+"/export"
  <#
      $VMJSON =
      "{
      #vmName"": ""$NewVMName"",
      ""disableNetwork"": true,
      ""removeNetworkDevices"": false,
      ""powerOn"": false,
      ""keepMacAddresses"": false,
      ""hostId"": ""$ESXiHostID"",
      ""datastoreId"": ""$ESXiHostDatastoreID""
      }"
  
  
      $VMJSON2 = New-Object -TypeName psobject -Property @{
      "vmName" = "rubrikSupport_test"
      "disableNetwork" = $true
      "removeNetworkDevices" = $false
      "powerOn" = $true
      "keepMacAddresses" = $false
      "hostId" = $ESXiHostID
      "datastoreId" = $ESXiHostDatastoreID
      }
  #>  
  $VMJSON3 = New-Object -TypeName psobject -Property @{
    #"vmName" = $NewVMName
    "removeNetworkDevices" = $false
    "powerOn" = $false
    "hostId" = $ESXiHostID
    "datastoreId" = $ESXiHostDatastoreID
    }    
  ###########################################
  # POST to REST API URL with VMJSON
  ###########################################
  $VMJSON = $VMJSON3 |ConvertTo-Json
  Try 
  {
    $Result = Invoke-RestMethod -Method Post -Uri $VMExportURL -Body $VMJSON -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
    
  }
  Catch 
  {
    $_.Exception.ToString()
    $error[0] | Format-List -Force | Out-file Results.txt -append -noclobber
  }
  $SourceVMName
  $VMSnapshotID
  $ESXiHostID
  $ESXiHostDatastoreID
  $VMJSON
  $Result | Out-file Results.txt -append -noclobber
  ###########################################
  # Waiting $VMExportTimeDelay seconds before processing next VM
  ###########################################
  "Waiting $VMExportTimeDelay seconds before processing next VM export."
  sleep $VMExportTimeDelay
  # End of per VM action below
}
# End of per VM action above
###############################################
# End of script
###############################################