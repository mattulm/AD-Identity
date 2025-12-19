<#
.SYNOPSIS
    Audits the Print Spooler service status on all Domain Controllers and sends a webhook alert if any are found RUNNING.

.DESCRIPTION
    1. Enumerates all Domain Controllers in the specified domain.
    2. Connects to each DC using specified credentials.
    3. Checks the status of the 'Spooler' service (Running/Stopped).
    4. Sends a Webhook alert (Teams/Slack) if any Spoolers are found RUNNING.

.PARAMETER Domain
    The target Domain FQDN (e.g., contoso.local).

.PARAMETER Username
    Username for authentication (e.g., 'DOMAIN\User' or 'User@domain.local').

.PARAMETER Password
    Cleartext password for authentication.

.PARAMETER WebhookUrl
    Slack or Teams Webhook URL for notifications.

.EXAMPLE
    .\Audit-SpoolerNotify.ps1 -Domain yourdomain.local -Username 'Administrator' -Password 'SecureP@ssword123' -WebhookUrl 'https://hooks.slack.com/services/...'
   
    # Note: Requires the 'ActiveDirectory' module to use Get-ADDomainController, or you can use the DNS method (See notes below).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Password,

    [string]$WebhookUrl
)

# --- Configuration ---
$ServiceName = "Spooler"
# ANSI Escape Sequences for Console Output Coloring
$ColorRed = "`e[91m"
$ColorYellow = "`e[93m"
$ColorGreen = "`e[92m"
$ColorReset = "`e[0m"

# ---------------------------------------------------------
# 1. DISCOVERY FUNCTION (AD based - Preferred in PowerShell)
# ---------------------------------------------------------
function Get-DomainControllers {
    param([string]$TargetDomain)
   
    Write-Host "[*] Querying Active Directory for Domain Controllers in $TargetDomain..."
   
    try {
        # Use Get-ADDomainController to find all DCs (Requires ActiveDirectory module)
        $DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
       
        if (-not $DCs) {
            Write-Warning "Could not find any Domain Controllers using Get-ADDomainController."
            # Fallback to DNS-based discovery if AD module is not available or fails
            $DCs = Get-DomainControllersDns $TargetDomain
        }
       
        Write-Host "[*] Found $($DCs.Count) Domain Controllers."
        return $DCs
    }
    catch {
        Write-Error "AD Lookup failed: $($_.Exception.Message)"
        # Fallback to DNS-based discovery
        return Get-DomainControllersDns $TargetDomain
    }
}

# DNS Fallback (Equivalent to the Python DNS logic)
function Get-DomainControllersDns {
    param([string]$TargetDomain)
   
    Write-Host "[*] Falling back to DNS SRV query for Domain Controllers..."
    $srvRecord = "_ldap._tcp.dc._msdcs.$TargetDomain"
   
    try {
        # Resolve-DnsName queries DNS records
        $DnsAnswers = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
        $DCs = $DnsAnswers.NameTarget | Select-Object -Unique | ForEach-Object { $_.TrimEnd('.') }
       
        if ($DCs.Count -eq 0) {
             Write-Error "Could not find domain '$TargetDomain' via DNS SRV record."
             exit 1
        }
       
        Write-Host "[*] Found $($DCs.Count) Domain Controllers via DNS."
        return $DCs
    }
    catch {
        Write-Error "DNS Lookup failed: $($_.Exception.Message)"
        exit 1
    }
}

# ---------------------------------------------------------
# 2. AUDIT FUNCTION (SCM based)
# ---------------------------------------------------------
function Check-SpoolerStatus {
    param(
        [string]$Target,
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        # Get-Service connects to the SCM via RPC/WMI to query service status
        # This requires appropriate permissions and for the target to be reachable
        $Service = Get-Service -Name $ServiceName -ComputerName $Target -Credential $Credential -ErrorAction Stop
       
        switch ($Service.Status) {
            "Running" { return "RUNNING" }
            "Stopped" { return "STOPPED" }
            default { return "State Code: $($Service.Status)" }
        }
    }
    catch {
        $ErrorMsg = $_.Exception.Message
        if ($ErrorMsg -like "*Access is denied*") {
            return "ACCESS_DENIED"
        }
        elseif ($ErrorMsg -like "*network path was not found*" -or $ErrorMsg -like "*timed out*") {
            return "UNREACHABLE"
        }
        else {
            # Return a short error for display
            return "RPC_ERROR"
        }
    }
}

# ---------------------------------------------------------
# 3. NOTIFICATION FUNCTION (Webhook)
# ---------------------------------------------------------
function Send-WebhookAlert {
    param(
        [string]$Url,
        [array]$VulnerableHosts,
        [string]$TargetDomain
    )

    if (-not $VulnerableHosts) {
        return
    }

    Write-Host "[*] Sending webhook alert to $Url..."

    # Format the list of hosts for the message body
    $HostsFormatted = $VulnerableHosts | ForEach-Object { "- $($_.hostname) ($($_.status))" }
    $HostsString = $HostsFormatted -join "`n"

    $MessageText = @"
🚨 **SECURITY ALERT: Print Spooler Running on DCs** 🚨

**Domain:** $TargetDomain
**Risk:** The Print Spooler service is RUNNING on the following Domain Controllers. This increases the attack surface for PrintNightmare/RPC exploits.

**Vulnerable Hosts:**
$HostsString

**Action Required:** Disable the Print Spooler service on these hosts immediately.
"@

    # Simple 'text' payload works for both Slack and Teams
    $Payload = @{ text = $MessageText } | ConvertTo-Json

    try {
        # Invoke-RestMethod sends an HTTP request
        Invoke-RestMethod -Uri $Url -Method Post -Body $Payload -ContentType 'application/json' -TimeoutSec 10 -ErrorAction Stop
        Write-Host "[+] Webhook alert sent successfully."
    }
    catch {
        Write-Error "[-] Webhook failed. Status: $($_.Exception.Response.StatusCode.value__), Resp: $($_.Exception.Response.GetResponseStream().ReadToEnd())"
    }
}

# ---------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------

# Create PSCredential object
$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

# 1. Discovery
$DCs = Get-DomainControllers -TargetDomain $Domain

Write-Host ""
# Output Header
"{0,-35} | {1,-25}" -f "Domain Controller", "Spooler Status"
Write-Host ("-" * 65)

$VulnerableList = @()

# 2. Audit
foreach ($DC in $DCs) {
    $Status = Check-SpoolerStatus -Target $DC -Credential $Credential
   
    $DisplayStatus = $Status
   
    # Color coding for Console Output
    switch ($Status) {
        "RUNNING" {
            $DisplayStatus = "${ColorRed}!! $Status !!${ColorReset}"
            $VulnerableList += @{ hostname = $DC; status = $Status }
        }
        "ACCESS_DENIED" {
            $DisplayStatus = "${ColorYellow}$Status${ColorReset}"
        }
        "STOPPED" {
            $DisplayStatus = "${ColorGreen}$Status${ColorReset}"
        }
    }
   
    "{0,-35} | {1,-25}" -f $DC, $DisplayStatus
}

Write-Host ("-" * 65)

# 3. Notification
if ($VulnerableList.Count -gt 0) {
    Write-Host "`n[!] Found $($VulnerableList.Count) DC(s) with Spooler RUNNING."
    if ($WebhookUrl) {
        Send-WebhookAlert -Url $WebhookUrl -VulnerableHosts $VulnerableList -TargetDomain $Domain
    }
    else {
        Write-Host "[*] No webhook provided. Skipping alert."
    }
}
else {
    Write-Host "`n[*] Compliance Check Passed: No Spoolers Running."
