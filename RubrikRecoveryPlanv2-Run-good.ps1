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
$Day = get-date -UFormat "%A"
#Determine by day of the week which csv file to run, i.e., Monday.csv.
$RecoveryPlanCSV = ("C:\RubrikRecoveryPlanv2\Advanced\" + $Day +".csv")
#RubrikRecoveryPlanA.csv"
$LogDirectory = "C:\RubrikRecoveryPlanv2\Advanced\Logs"
# Username and password passed by secure files which can only run from configuration workstation\server.
$Credentials = IMPORT-CLIXML "C:\Rubrik\RubrikExporter\SecureCredentials.xml"
$RubrikUser = $Credentials.UserName
$Credentials.Password | ConvertFrom-SecureString
$RubrikPassword = $Credentials.GetNetworkCredential().password
#$PostUserName=Inventory_Admin@nittsu.com
#$PostPassword= CoinToss71
$Credential2 = IMPORT-CLIXML "C:\RubrikRecoveryPlanv2\Advanced\SecureCredentialsReport.xml"
$ReportUser = $Credential2.UserName
$ReportPassword = $Credential2.GetNetworkCredential().Password
$pair = "${ReportUser}:${ReportPassword}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$headers2 = @{ Authorization = $basicAuthValue }
# VM suffix is added to the end of each VM name as its registered in the vCenter, set to $null if you just want the VM name as is, I.E for recovery with existing VM gone
# Ensure you configure this exactly the same in the configure and stop scripts otherwise they won't find any VMs to configure or stop the live mount on
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
#region TODO Starting logging & importing the CSV
################################################
$Now = get-date
$Log = $LogDirectory + "\Rubrik-ExportnRunLog-" + $Now.ToString("yyyy-MM-dd") + "@" + $Now.ToString("HH-mm-ss") + ".log"
Start-Transcript -Path $Log -NoClobber 
$RecoveryPlanVMs = import-csv $RecoveryPlanCSV
#endregion 
################################################
#region TODO Building Rubrik API string & invoking REST API
################################################
$BaseURL = "https://" + $RubrikCluster + "/api/v1/"
$RubrikSessionURL = $BaseURL + "session"
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RubrikUser+":"+$RubrikPassword))}
#$Header2 = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ReportUser+":"+$ReportPassword))}
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
<#
    ################################################
    #region TODO Building Reporting API string & invoking REST API
    ################################################
    $BaseURL2 = "http://" + $ReportingNode + "/neus/isd/Windowsservertracking.nsf"
    $ReportingSessionURL = $BaseURL2 + "session"
    $Header2 = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ReportUser+":"+$ReportPassword))}
    $Type = "application/json"
    # Authenticating with API
    Try 
    {
    $ReportSessionResponse = Invoke-RestMethod -Uri $ReportingSessionURL -Headers $Header2 -Method POST -ContentType $Type
    }
    Catch 
    {
    $_.Exception.ToString()
    $error[0] | Format-List -Force
    }
    # Extracting the token from the JSON response
    $ReportingSessionHeader = @{'Authorization' = "Bearer $($ReportSessionResponse.token)"}
    #endregion 
#>
###############################################
#region TODO Getting list of VMs
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
# For troubleshooting output the list of VMs found: $VMList | Select Name | Sort-Object Name,id | Format-Table -AutoSize
#endregion 
###############################################
#region TODO Getting list of Hosts
###############################################
$VMHostListURL = $BaseURL+"vmware/host"
Try 
{
  $VMHostListJSON = Invoke-RestMethod -Uri $VMHostListURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
  $VMHostList = $VMHostListJSON.data
}
Catch 
{
  $_.Exception.ToString()
  $Error[0] | Format-List -Force
}
#endregion 
###################################################################
#region TODO Start Per VM Actions here
###################################################################
"Starting per VM RecoveryPlan Actions with VMSuffix:$VMSuffix"
foreach ($VM in $RecoveryPlanVMs)
{
  ###############################################
  # Setting the variables for the current VM
  ###############################################
  $VMName = $VM.VMName
  $VMHostSelection = $VM.HostSelection
  $Datastore = $VM.Datastore
  $VMDisableNetwork = $VM.DisableNetwork
  $VMRemoveNetworkDevices = $VM.RemoveNetworkDevices
  $VMRubrikPowerOn = $VM.RubrikPowerOn
  $VMRunScriptsinLiveMount = $VM.RunScriptsinLiveMount
  $VMPreFailoverScript = $VM.PreFailoverScript
  $VMPostFailoverScriptDelay = $VM.PostFailoverScriptDelay
  $VMPostFailoverScript = $VM.PostFailoverScript
  $VMNextVMFailoverDelay = $VM.NextVMFailoverDelay
  $VMPreFailoverUserPrompt = $VM.PreFailoverUserPrompt
  $VMPostFailoverUserPrompt = $VM.PostFailoverUserPrompt
  # Setting VM live mount name
  #Disabled in this script for exports  
  # $VMLiveMountName = $VMName + $VMSuffix  
  # Inserting space in log for readability
  "--------------------------------------------"
  "Performing Action for VM:$VMName"
  # Giving the user 3 seconds to see
  sleep 3
  #endregion 
  ###################################################################
  #region TODO VM Pre-Failover User Prompt
  ###################################################################
  if ($VMPreFailoverUserPrompt -ne "")
  {
    # Setting title and user prompt
    $PromptTitle = "Pre-Failover Prompt"
    $PromptMessage = "VM:$VMName 
    $VMPreFailoverUserPrompt"
    # Defining options
    $Continue = New-Object System.Management.Automation.Host.ChoiceDescription "&Continue", `
    "Continues to run the recovery plan"
    $Stop = New-Object System.Management.Automation.Host.ChoiceDescription "&Stop", `
    "Stops the recovery plan altogether"
    $PromptOptions = [System.Management.Automation.Host.ChoiceDescription[]]($Continue, $Stop)
    # Prompting user and defining the result
    $PromptResult = $host.ui.PromptForChoice($PromptTitle, $PromptMessage, $PromptOptions, 0) 
    switch ($PromptResult)
    {
        0 {"User Selected Continue Recovery Plan"}
        1 {"User Selected Stop Recovery Plan"}
    }
    # Performing the exit action if selected
    if ($PromptResult -eq 1)
    {
      # Stopping transcript
      Stop-Transcript
      # Killing PowerShell script process
      kill $PID
    }
  }
  #endregion 
  ###############################################
  #region TODO Getting VM ID and VM snapshot info
  ###############################################
  $SnapshotArray=@()
  # Selecting VM ID, if multiple will cycle through each to find a snapshot (can happen if the VM name already exists in the vCenter)
  $VMIDs = $VMList | Where-Object {$_.name -eq $VMName}
  ForEach ($VMID in $VMIDs)
  {
    # Setting values
    $VMIDName = $VMID.name
    $VMID = $VMID.id
    $VMSnapshotID = $null
    $VMSnapshotDate = $null
    # Building Snapshot URL
    $VMSnapshotURL = $baseURL+"vmware/vm/"+$VMID+"/snapshot"
    # Getting list of snapshots for the VMID
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
    # Building a table of all the snapshots for the VM
    ForEach ($VMSnap in $VMSnapshot)
    {
      $SnapshotID = $VMSnap.id
      $SnapshotDateOriginal = $VMSnap.date
      # Converting from string to datetime format
      $SnapshotDateFormat1 = $SnapshotDateOriginal.Replace("T"," ").Replace("Z"," ").TrimEnd()
      $SnapshotDateFormat2 = $SnapshotDateFormat1.Substring(0,$SnapshotDateFormat1.Length-4)
      # Final conversion
      $SnapshotDate = ([datetime]::ParseExact($SnapshotDateFormat2,”yyyy-MM-dd HH:mm:ss”,$null))
      # Adding row to table array with information gathered
      $SnapshotArrayLine = new-object PSObject
      $SnapshotArrayLine | Add-Member -MemberType NoteProperty -Name "VMIDName" -Value "$VMIDName"
      $SnapshotArrayLine | Add-Member -MemberType NoteProperty -Name "VMID" -Value "$VMID"
      $SnapshotArrayLine | Add-Member -MemberType NoteProperty -Name "SnapshotID" -Value "$SnapshotID"
      $SnapshotArrayLine | Add-Member -MemberType NoteProperty -Name "SnapshotDate" -Value "$SnapshotDate"
      $SnapshotArray += $SnapshotArrayLine
    }
  }
  #endregion 
  ###############################################
  #region TODO Selecting VMID and VMSnapshotID where a VMSnapshotID exists
  ###############################################
  $VMSnapshotID = $SnapshotArray | Where-Object {$_.SnapshotID -ne ""} | Sort-Object -Descending SnapshotDate | Select -ExpandProperty SnapshotID -First 1
  $VMSnapshotDate = $SnapshotArray | Where-Object {$_.SnapshotID -eq $VMSnapshotID} | Sort-Object -Descending SnapshotDate | Select -ExpandProperty SnapshotDate -First 1
  $VMID = $SnapshotArray | Where-Object {$_.SnapshotID -eq $SnapshotID} | Select -ExpandProperty VMID -First 1
  # Setting VMID value if not found (for logging)
  IF ($VMID -eq $null)
  {
    $VMID = " VM and/or Snapshot Not Found In Rubrik"
  }
  #endregion 
  ###########################################
  #region TODO Running pre-failover script if RunScriptsinTest is enabled and script configured
  ###########################################
  if (($VMRunScriptsinLiveMount -eq "TRUE") -and ($VMPreFailoverScript -ne ""))
  {
    Try 
    {
      "Running Pre-FailoverScript:$VMPreFailoverScript"
      invoke-expression $VMPreFailoverScript
    }
    Catch 
    {
      $_.Exception.ToString()
      $error[0] | Format-List -Force
    }
  }
  #endregion 
  ###########################################
  #region TODO Selecting VM host, only selecting hosts with datastores ensures that you aren't selecting a host ID which is replicated vs usable by the Rubrik cluster
  ###########################################
  IF ($VMHostSelection -ne "RANDOM")
  {
    # ESXi hostname has been specified, selecting the host
   
    $VMHostID = $VMHostList |  Where-Object {($_.name -eq $VMHostSelection) -and ($_.datastores -ne $null)} | Select-Object -ExpandProperty id -First 1
    $VMHostName = $VMHostList |  Where-Object {$_.id -eq $VMHostID} | Select -ExpandProperty name -First 1
    $ESXiHostInfo = $VMHostList | where {$_.name -eq "$VMHostName"}
  }
  # Setting to RANDOM if no ESXi host found or set to RANDOM
  IF (($VMHostID -eq $null) -or ($VMHostSelection -eq "RANDOM"))
  {
    $VMHostID = $VMHostList | Where-Object {$_.datastores -ne $null} | Get-Random | Select -ExpandProperty id
    $VMHostName = $VMHostList |  Where-Object {$_.id -eq $VMHostID} | Select -ExpandProperty name -First 1
  }
  ###############################################
  # Getting Datastore ID  -  Needed for export.
  ###############################################
  $ESXiHostDatastores = $ESXiHostInfo.datastores
  $ESXiHostDatastoreID = $ESXiHostDatastores | Where {$_.name -eq "$Datastore"} | Select -ExpandProperty id
  ###############################################
  #endregion 
  ###########################################
  #region TODO Logging settings
  ###########################################
  "Using the following values:
    VMID:$VMID
    HostName:$VMHostName
    DatastoreID: $ESXiHostDatastoreID
    SnapshotID:$VMSnapshotID
    SnapshotDate:$VMSnapshotDate
    DisableNetwork:$VMDisableNetwork
    RemoveNetworkDevices:$VMRemoveNetworkDevices
  RubrikPowerOn:$VMRubrikPowerOn"
  #endregion 
  ###########################################
  #region TODO Creating JSON & configuring URL
  ###########################################
  # Setting default if not specified in CSV, or not configured correctly, defaulting to safe set of options
  if (($VMDisableNetwork -eq "") -or ($VMDisableNetwork -ne "FALSE")){$VMDisableNetwork = "true"}
  if (($VMRemoveNetworkDevices -eq "") -or ($VMRemoveNetworkDevices -ne "TRUE")){$VMRemoveNetworkDevices = "false"}
  if (($VMRubrikPowerOn -eq "") -or ($VMRubrikPowerOn -ne "TRUE")){$VMRubrikPowerOn = "false"}
  # Forcing to lower case to compensate for excel auto-correct capitalizing 
  $VMDisableNetwork = $VMDisableNetwork.ToLower()
  $VMRemoveNetworkDevices = $VMRemoveNetworkDevices.ToLower()
  $VMRubrikPowerOn = $VMRubrikPowerOn.ToLower()
  $VMJSON3 = New-Object -TypeName psobject -Property @{
    #"vmName" = $NewVMName
    "removeNetworkDevices" = $false
    "powerOn" = $false
    "hostId" = $VMHostID
    "datastoreId" = $ESXiHostDatastoreID
    }    
  
  ###########################################
  # POST to REST API URL with VMJSON
  ###########################################
  $VMLMJSON = $VMJSON3 |ConvertTo-Json
  <#
      $VMLMJSON =
      "{
      ""disableNetwork"": $VMDisableNetwork,
      ""removeNetworkDevices"": $VMRemoveNetworkDevices,
      ""powerOn"": $VMRubrikPowerOn,
      ""hostId"":""$VMHostID"",
      ""datastoreID"":""$ESXiHostDatastoreID"",
      ""unregisterVm"":false
      }"
  #>
  <#  
      ""vmName"": ""$VMLiveMountName"",

      $VMLMJSON1 = New - Object - TypeName psobject - Property @ {
      "VMName" = $VMName
      "disableNetwork" = $true,
      "removeNetworkDevices" = $false,
      "powerOn" = $false,
      "hostId" = $VMHostID,
      "datastoreID" = $ESXiHostDatastoreID
      }

      $VMLMJSON = $VMLMJSON1 | ConvertTo-Json
 
      ""vmName"": ""$VMLiveMountName"",
  #>
  $VMExportURL = $baseURL+"vmware/vm/snapshot/"+$VMSnapshotID+"/export"
  #endregion 
  ###########################################
  #region TODO POST to REST API URL with VMJSON, but only if a VMID is found
  ###########################################
  IF ($VMSnapshotID -ne $null)
  {
    Try 
    {
      "Starting Export of VM:$vmName"
      $VMLiveMountPOST = Invoke-RestMethod -Method Post -Uri $VMExportURL -Body $VMLMJSON -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
      $VMOperationSuccess = $TRUE
    }
    Catch 
    {
      $VMLiveMountPOST
      $_.Exception.ToString()
      $error[0] | Format-List -Force
      $VMOperationSuccess = $FALSE
    }
    ##############################TEST#####################
    ################################################
    # Getting Job status on a loop
    ################################################
    # Getting Status URL
    $ExportJobStatusURL = $VMLiveMountPOST.links.href
    #$uri = (([xml]$response.Content).LogonSession.Links.Link | where-object {$_.Type -eq 'JobReferenceList' }).Href
    #$ExportJobStatusResult = $VMliveMountPOST.links.href[0]
    # Setting counter
    $ExportobStatusCount = 0
    DO
    {
      $ExportobStatusCount ++
      # Getting status
      Try 
      {
        $ExportJobStatusResponse = Invoke-RestMethod -Uri $ExportJobStatusURL -Headers $RubrikSessionHeader
        # Setting status
        $OFS = "`r`n"
        $ExportJobStatusQuery = $ExportJobStatusResponse.links.href
        $ExportJobStatusQuery + $OFS | Out-File -Encoding Ascii -Append -FilePath C:\RubrikRecoveryPlanv2\Advanced\Logs\Rubrik-Query-$Day.txt
        $ExportJobStatus = $ExportJobStatusResponse.status
        $ExportJobProgress = $ExportJobStatusResponse.Progress
        $ExportJobProgress
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
    } Until (($ExportJobStatus -eq "SUCCEEDED") -OR ($ExportJobStatus -eq "FAILED") -OR ($ExportJobStatusCount -eq 5760))
    ################################################
    # Perform any next actions you want here
    ################################################
    IF ($ExportJobStatus -eq "SUCCEEDED")
    {
      #  invoke-restMethod 'http://exn101.nittsu.com/NEUS/ISD/WindowsServerTracking.nsf/agtUpdateMachine?OpenAgent&Var=$vmName&Var=90&Var=$Startime&Var=$Endtime&Var=Success'
      $ExportJoburl2 = $Exportjobstatusresponse.links.href[0]
      $ExportJoburl2
      $HDTotal = Invoke-restmethod -uri $ExportJoburl2 -Headers $RubrikSessionheader 
      
      #      $VMID2 = $HDTotal.id
      $vmname1 = $HDTotal.name
      $vmname1      
      $VdiskID = $HDTotal.virtualDiskIds
      $VMTotal = 0
      #      $Vdisk = 0
     
      foreach($vDisk in $VdiskID)
        {
        $DiskURL = $baseURL+"vmware/vm/virtual_disk/$vDisk"
        $Result3 = Invoke-restmethod -uri $DiskURL -Headers $RubrikSessionheader
             $Total=$Result3.size 
             $VMTotal += $Total
             $VMTotal
        }
        $VMTotalFin = ($VMTotal/1024) * .000001
      "Using the following values:
        TotalSize:$VMTotal
          VdiskID:$VMTotalFin"
                      
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
       
      # Submit for user viewing to http://exn101.nittsu.com/neus/isd/windowsservertracking.nsf/vwByTSMBackup?OpenView 
      $StartTime = $ExportSDate.ToLocalTime()
      $EndTime  = $ExportEDate.ToLocalTime()
      invoke-webrequest -uri "http://exn101.nittsu.com/NEUS/ISD/WindowsServerTracking.nsf/agtUpdateMachine?OpenAgent&Var=$vmName&Var=$VMTotalFin&Var=$StartTime&Var=$EndTime&Var=Success" -Headers $headers2 
    }
    ################################################
    # End of script
    ################################################
    ##############################TEST#####################
    # Logging result
    "OperationSuccess:$VMOperationSuccess"
  }
  ELSE
  {
    $VMOperationSuccess = $FALSE
    # Logging result
    "OperationSuccess:$VMOperationSuccess"
  }
  #endregion 
  ###########################################
  #region TODO Running post-failover script if RunScriptsinTest is enabled, script configured and test started
  ###########################################
  if (($VMRunScriptsinLiveMount -eq "TRUE") -and ($VMPostFailoverScript -ne "") -and ($VMOperationSuccess -eq $TRUE))
  {
    # Waiting sleep delay for post script
    "Sleeping $VMPostFailoverScriptDelay seconds for VMPostFailoverScriptDelay"
    sleep $VMPostFailoverScriptDelay
    Try 
    {
      "Running Post-FailoverScript:$VMPostFailoverScript"
      invoke-expression $VMPostFailoverScript
    }
    Catch 
    {
      $_.Exception.ToString()
      $error[0] | Format-List -Force
    }
  }
  #endregion 
  ###########################################
  #region TODO Waiting for VMNextVMFailoverDelay and Post-Failover Prompt (if configured) if start test was a success
  ###########################################
  IF ($VMOperationSuccess -eq $TRUE)
  {
    # Ignoring sleep delay if VM isn't set to power on, boot delay will be observed only when powering on VMs
    IF ($VMRubrikPowerOn -eq "true")
    {
      "Sleeping $VMNextVMFailoverDelay seconds for VMNextVMFailoverDelay"
      sleep $VMNextVMFailoverDelay
    }
    #endregion 
    ###################################################################
    #region TODO VM Post-Failover User Prompt
    ###################################################################
    if ($VMPostFailoverUserPrompt -ne "")
    {
      # Setting title and user prompt
      $PromptTitle = "Post-Failover Prompt"
      $PromptMessage = "VM:$VMName 
      $VMPostFailoverUserPrompt"
      # Defining options
      $Continue = New-Object System.Management.Automation.Host.ChoiceDescription "&Continue", `
      "Continues to run the recovery plan"
      $Stop = New-Object System.Management.Automation.Host.ChoiceDescription "&Stop", `
      "Stops the recovery plan altogether"
      $PromptOptions = [System.Management.Automation.Host.ChoiceDescription[]]($Continue, $Stop)
      # Prompting user and defining the result
      $PromptResult = $host.ui.PromptForChoice($PromptTitle, $PromptMessage, $PromptOptions, 0) 
      switch ($PromptResult)
      {
        0 {"User Selected Continue Recovery Plan"}
        1 {"User Selected Stop Recovery Plan"}
      }
      # Performing the exit action if selected
      if ($PromptResult -eq 1)
      {
        # Stopping transcript
        Stop-Transcript
        # Killing PowerShell script process
        kill $PID
      }
    }
    # End of "Waiting for VMPostFailoverUserPrompt and Post-Failover Prompt (if configured) if start test was a success" below
  }
  # End of "Waiting for VMPostFailoverUserPrompt and Post-Failover Prompt (if configured) if start test was a success" above
  #
  # End of per VM actions below
}
# End of per VM actions above
#
# Inserting space in log for readability
"--------------------------------------------"
"End of RecoveryPlan Script"
#endregion 
################################################
#region TODO Stopping logging
################################################
Stop-Transcript
###############################################
#endregion  TODO End of script
###############################################
