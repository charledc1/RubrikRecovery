<#
    .Description
    #region TODO Start of the script - Description, Requirements 
    ########################################################################################################################
    # Written by: Derek Charleston derek_charleston@nittsu.com
    ################################################
    # Description:
    # This script runs a export to NFS storage for VMs specified in a CSV to be backed up to tape.
    ################################################ 
    # Requirements:
    # - Run PowerShell as administrator with command "Set-ExecutionPolcity unrestricted" on the host running the script
    # - A Rubrik cluster or EDGE appliance, network access to it and credentials to login
    # - A CSV with the following fields: VMName,HostSelection,Datastore,DisableNetwork,RemoveNetworkDevices,RubrikPowerOn,RunScriptsinLiveMount,PreFailoverScript,PostFailoverScriptDelay,PostFailoverScript,NextVMFailoverDelay,PreFailoverUserPrompt,PostFailoverUserPrompt,vCenterPowerOn,ConfigureNIC,PortGroup,ConnectNIC
    # - Example CSV Line = DemoApp1-VM01,192.168.1.14,RUBRIK_EXPORT,FALSE,FALSE,FALSE,FALSE,,0,,0,,,TRUE,TRUE,Isolated,TRUE
    # - Valid options for HostSelection are RANDOM (uses the existing ESXi host of the VM if recovering to prod) or the name of the ESXi host as registred in the vCenter
    # - The options DisableNetwork,PowerOn,RunScriptsinLiveMount are only used in this Run script, not in the configure script
    # - Valid options for DisableNetwork,RemoveNetworkDevices,PowerOn,RunScriptsinLiveMount are TRUE or FALSE
    # - Valid options for PostFailoverScriptDelay,NextVMFailoverDelay is 0 - any number of seconds
    # - If no script is specified for PreFailoverScript,PostFailoverScript then nothing is run
    # - If no user prompt is specified for PreFailoverUserPrompt,PostFailoverUserPrompt then the user isn't prompted, this choice can be made per VM
    # - This script always fails over to the latest snapshot available
    ################################################
    # Legal Disclaimer:
    # This script is written by Derek Charleston is not supported under any support program or service. 
    # All scripts are provided AS IS without warranty of any kind. 
    # The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
    # The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
    # In no event shall its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever 
    # (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) 
    # arising out of the use of or inability to use the sample scripts or documentation, even if the author has been advised of the possibility of such damages.
    ################################################
    # Configure the variables below for the Rubrik Cluster
#>
$RubrikCluster = "10.254.215.173"
#Determine by day of the week which csv file to run, i.e., Monday.csv.
$Day = get-date -UFormat "%A"
#RubrikRecoveryPlanA.csv"
$LogDirectory = "C:\RubrikRecoveryPlanv2\Advanced\Logs"
# Username and password passed by secure files which can only run from configuration workstation\server.
$Credentials = IMPORT-CLIXML "C:\RubrikRecoveryPlanv2\Advanced\SecureCredentials.xml"
$RubrikUser = $Credentials.UserName
$Credentials.Password | ConvertFrom-SecureString
$RubrikPassword = $Credentials.GetNetworkCredential().password
$Credential2 = IMPORT-CLIXML "C:\RubrikRecoveryPlanv2\Advanced\SecureCredentialsReport.xml"
$ReportUser = $Credential2.UserName
$ReportPassword = $Credential2.GetNetworkCredential().Password
$pair = "${ReportUser}:${ReportPassword}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$headers2 = @{ Authorization = $basicAuthValue }

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
#endregion 
################################################
#region TODO Building Rubrik API string & invoking REST API
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
#endregion
######################################################### 
#Start Logging
$Now = get-date
$Log = $LogDirectory + "\Rubrik-Export-Status-Log-" + $Now.ToString("yyyy-MM-dd") + "@" + $Now.ToString("HH-mm-ss") + ".log"
Start-Transcript -Path $Log -NoClobber 

    
###############################################
# Getting Job status on a loop
################################################
# Setting counter
    
    $ExportJobStatusCount = 0
    $ExportJobStatus=0
    
    $ExportJobStatusResponse1 =  get-Content -Path C:\RubrikRecoveryPlanv2\Advanced\Logs\Rubrik-Query-$day.txt
    
         foreach($ExportJob in $ExportJobStatusResponse1)
         { 
           Do
           {$ExportJobStatusCount++
             Try 
             {
               $ExportJob
               $ExportJobStatusResponse = Invoke-RestMethod -Uri $ExportJob -Headers $RubrikSessionHeader
               $ExportJobStatus = $ExportJobStatusResponse.status
               $VMOperationSuccess = $TRUE
             }
             Catch 
             {
               $_.Exception.ToString()
               $Error[0] | Format-List -Force
               $ExportJobStatus = "FAILED"
             }
      
             # Output to host
             "ExportJobStatus: $ExportJobStatus"
             # Waiting 15 seconds before trying again, but only if not succeeded
             IF ($ExportJobStatus -ne "SUCCEEDED")
             {
               sleep 15
             }
            
           # Will run until it succeeds, fails, or hits 24 hours (5760 is number of seconds in a day / 15)
            }
           Until (($ExportJobStatus -eq "SUCCEEDED") -OR ($ExportJobStatus -eq "FAILED") -OR ($ExportJobStatusCount -eq 5760))
           ################################################
           # Perform any next actions you want here
           ################################################
           
             IF ($ExportJobStatus -eq "SUCCEEDED")
             {
               #  Get Results URL link and HD drive space used
               $ExportJoburl2 = $ExportJobStatusResponse.links.href[0]
               "ExportJobURL: $ExportJoburl2"
               $HDTotal = Invoke-restmethod -uri $ExportJoburl2 -Headers $RubrikSessionheader 
               
               #  Get VM export name and Original name of VM.
               $vmname1 = $HDTotal.name
               $vmname = ($vmname1).split(" ")[0]
               "ExportJobVMname: $vmname1"
               "OriginalVMName: $vmname"  
               
               #  Get HD Totals  
               $VdiskID = $HDTotal.virtualDiskIds
               $VMTotal = 0
               foreach($vDisk in $VdiskID)
                {
                    $DiskURL = $baseURL+"vmware/vm/virtual_disk/$vDisk"
                    $Result3 = Invoke-restmethod -uri $DiskURL -Headers $RubrikSessionheader
                    $Total=$Result3.size 
                    "DriveSize: $Total"
                    $VMTotal += $Total
                }
               $VMTotalFin = ($VMTotal/1024) * .000001
               "Using the following values:
               TotalSize: $VMTotal
               TotalSizeinGB: $VMTotalFin"
               
               # Calculate the Start time of Export       
               $ExportSTimeOrg = $ExportJobStatusResponse.startTime
               $ExportSDateFormat1 = $ExportSTimeOrg.Replace("T"," ").Replace("Z"," ").TrimEnd()
               $ExportSDateFormat2 = $ExportSDateFormat1.Substring(0,$ExportSDateFormat1.Length-4)
               $ExportSDate = ([datetime]::ParseExact($ExportSDateFormat2,”yyyy-MM-dd HH:mm:ss”,$null))
               
               # Final End Time conversion
               $ExportETimeOrg = $ExportJobStatusResponse.endTime
               $ExportEDateFormat1 = $ExportETimeOrg.Replace("T"," ").Replace("Z"," ").TrimEnd()
               $ExportSDateFormat3 = $ExportEDateFormat1.Substring(0,$ExportEDateFormat1.Length-4)
               $ExportEDate = ([datetime]::ParseExact($ExportSDateFormat3,”yyyy-MM-dd HH:mm:ss”,$null)) 
               
               #  Show Start time and End time 
               $StartTime = $ExportSDate.ToLocalTime()
               $EndTime  = $ExportEDate.ToLocalTime()
               "Start Time of Export: $StartTime"
               "End Time of Export: $:EndTime"

               # Post results to Website
               invoke-webrequest -uri "http://exn101.nittsu.com/NEUS/ISD/WindowsServerTracking.nsf/agtUpdateMachine?OpenAgent&Var=$vmname&Var=$VMTotalFin&Var=$StartTime&Var=$EndTime&Var=Success" -Headers $headers2 
             }
           # Logging result
           "OperationSuccess:$VMOperationSuccess"
           "----------------------------------------------------------------"
         }         
  IF ($ExportJobStatus -eq "Failed")  
  {
    $VMOperationSuccess = $FALSE
    
                # Logging result
                "OperationSuccess:$VMOperationSuccess"
                #  
                $ExportJoburl2 = $ExportJobStatusResponse.links.href[0]
                "ExportJobURL: $ExportJoburl2"
                $HDTotal = Invoke-restmethod -uri $ExportJoburl2 -Headers $RubrikSessionheader 
      
                #  $VMID2 = $HDTotal.id
                $vmname1 = $HDTotal.name
                $vmname = ($vmname1).split(" ")[0]
                "ExportJobVMname: $vmname1"
                "OriginalVMName: $vmname"      
                $VdiskID = $HDTotal.virtualDiskIds
                $VMTotal = 0
                    
               foreach($vDisk in $VdiskID)
               {
                 $DiskURL = $baseURL+"vmware/vm/virtual_disk/$vDisk"
                 $Result3 = Invoke-restmethod -uri $DiskURL -Headers $RubrikSessionheader
                 $Total=$Result3.size 
                 "DriveSize: $Total"
                 $VMTotal += $Total
               }
               
               $VMTotalFin = ($VMTotal/1024) * .000001
               
               "Using the following values:
               TotalSize: $VMTotal
               TotalSizeinGB: $VMTotalFin"
                      
               $ExportSTimeOrg = $ExportJobStatusResponse.startTime
               $ExportSDateFormat1 = $ExportSTimeOrg.Replace("T"," ").Replace("Z"," ").TrimEnd()
               $ExportSDateFormat2 = $ExportSDateFormat1.Substring(0,$ExportSDateFormat1.Length-4)
               
               # Final Start Time conversion
               $ExportSDate = ([datetime]::ParseExact($ExportSDateFormat2,”yyyy-MM-dd HH:mm:ss”,$null))
               $ExportETimeOrg = $ExportJobStatusResponse.endTime
               $ExportEDateFormat1 = $ExportETimeOrg.Replace("T"," ").Replace("Z"," ").TrimEnd()
               $ExportSDateFormat3 = $ExportEDateFormat1.Substring(0,$ExportEDateFormat1.Length-4)
               
               # Final End time conversion 
               $ExportEDate = ([datetime]::ParseExact($ExportSDateFormat3,”yyyy-MM-dd HH:mm:ss”,$null)) 
               $StartTime = $ExportSDate.ToLocalTime()
               $EndTime  = $ExportEDate.ToLocalTime()
               invoke-webrequest -uri "http://exn101.nittsu.com/NEUS/ISD/WindowsServerTracking.nsf/agtUpdateMachine?OpenAgent&Var=$vmname&Var=$VMTotalFin&Var=$StartTime&Var=$EndTime&Var=Failure" -Headers $headers2 
             }
  #endregion 
  # Inserting space in log for readability
"--------------------------------------------"
"End of Status Script"
#endregion 
################################################
#region TODO Stopping logging
################################################
Stop-Transcript
###############################################
#endregion  TODO End of script
###############################################