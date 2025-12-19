#!/usr/bin/env python3
"""
Script Name: audit_spooler_notify.py
Description:
    1. Enumerates all Domain Controllers via DNS SRV records.
    2. Connects to the Service Control Manager (SCM) on each DC.
    3. Checks the status of the 'Spooler' service (Running/Stopped).
    4. Sends a Webhook alert (Teams/Slack) if any Spoolers are found RUNNING.

Usage:
    python3 audit_spooler_notify.py yourdomain.local -u <USER> -p <PASSWORD> --webhook <URL>
    python3 audit_spooler_notify.py yourdomain.local -u <USER> --ntlm <HASH> --webhook <URL>

Dependencies:
    impacket, dnspython, requests
"""

import argparse
import sys
import logging
import json
import requests
import dns.resolver
from impacket.dcerpc.v5 import transport, scmr

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%H:%M:%S')

# ---------------------------------------------------------
# 1. DISCOVERY FUNCTION (DNS based)
# ---------------------------------------------------------
def get_domain_controllers(domain):
    """
    Queries DNS for all Domain Controllers in the domain using SRV records.
    This removes the need to know a specific DC IP beforehand.
    """
    logging.info(f"[*] Querying DNS for Domain Controllers in {domain}...")
    dcs = []
    try:
        # The standard SRV record for DCs in AD
        srv_record = f'_ldap._tcp.dc._msdcs.{domain}'
        answers = dns.resolver.resolve(srv_record, 'SRV')
        for rdata in answers:
            # The target field contains the FQDN of the DC
            dc_fqdn = str(rdata.target).rstrip('.')
            dcs.append(dc_fqdn)
    except dns.resolver.NXDOMAIN:
        logging.error(f"[!] Could not find domain '{domain}'. Check spelling or DNS settings.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"[!] DNS Lookup failed: {e}")
        sys.exit(1)
   
    logging.info(f"[*] Found {len(dcs)} Domain Controllers.")
    return dcs

# ---------------------------------------------------------
# 2. AUDIT FUNCTION (RPC/SCMR based)
# ---------------------------------------------------------
def check_spooler_status(target, domain, username, password, lmhash, nthash):
    """
    Connects to the Service Control Manager via RPC over SMB
    and checks the 'Spooler' service status.
    """
    # Create the binding string for the Service Control Manager pipe
    binding = r'ncacn_np:{}[\pipe\svcctl]'.format(target)
   
    try:
        # Establish the RPC Transport
        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.set_credentials(username, password, domain, lmhash, nthash)
       
        # Connect to the Remote Procedure Call interface
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
       
        # 1. Open the Service Control Manager
        ans = scmr.hROpenSCManagerW(dce)
        scManagerHandle = ans['lpScHandle']
       
        # 2. Open the Print Spooler Service
        ans = scmr.hROpenServiceW(dce, scManagerHandle, 'Spooler')
        serviceHandle = ans['lpServiceHandle']
       
        # 3. Query the Service Status
        ans = scmr.hRQueryServiceStatus(dce, serviceHandle)
        state = ans['lpServiceStatus']['dwCurrentState']
       
        # Cleanup
        scmr.hRCloseServiceHandle(dce, serviceHandle)
        scmr.hRCloseServiceHandle(dce, scManagerHandle)
       
        # Return state
        if state == scmr.SERVICE_RUNNING:
            return "RUNNING"
        elif state == scmr.SERVICE_STOPPED:
            return "STOPPED"
        else:
            return f"State Code: {state}"

    except Exception as e:
        error_msg = str(e)
        if 'STATUS_ACCESS_DENIED' in error_msg or '0x00000005' in error_msg:
            return "ACCESS_DENIED"
        elif 'Connection refused' in error_msg or 'timed out' in error_msg:
            return "UNREACHABLE"
        else:
            # Return short error for display
            return "RPC_ERROR"

# ---------------------------------------------------------
# 3. NOTIFICATION FUNCTION (Webhook)
# ---------------------------------------------------------
def send_webhook_alert(url, vulnerable_hosts, domain):
    """
    Sends a formatted JSON payload to a Slack or MS Teams webhook.
    """
    if not vulnerable_hosts:
        return

    logging.info(f"[*] Sending webhook alert to {url}...")

    # Format the list of hosts for the message body
    hosts_formatted = "\n".join([f"- {host['hostname']} ({host['status']})" for host in vulnerable_hosts])
   
    message_text = (
        f"🚨 **SECURITY ALERT: Print Spooler Running on DCs** 🚨\n\n"
        f"**Domain:** {domain}\n"
        f"**Risk:** The Print Spooler service is RUNNING on the following Domain Controllers. "
        f"This increases the attack surface for PrintNightmare/RPC exploits.\n\n"
        f"**Vulnerable Hosts:**\n{hosts_formatted}\n\n"
        f"**Action Required:** Disable the Print Spooler service on these hosts immediately."
    )

    # Simple 'text' payload works for both Slack and Teams
    payload = {"text": message_text}

    try:
        response = requests.post(
            url,
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        if response.status_code == 200:
            logging.info("[+] Webhook alert sent successfully.")
        else:
            logging.error(f"[-] Webhook failed. Status: {response.status_code}, Resp: {response.text}")
    except Exception as e:
        logging.error(f"[-] Failed to send webhook: {e}")

# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Audit DC Print Spoolers and Alert via Webhook.")
   
    # Required Domain
    parser.add_argument("domain", help="Target Domain FQDN (e.g. contoso.local)")
   
    # Credentials
    parser.add_argument("-u", "--username", required=True, help="Username for authentication")
   
    # Auth Group (Password OR Hash)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-p", "--password", help="Cleartext password")
    auth_group.add_argument("--ntlm", help="NTLM Hash (Format: 'LM:NT' or just 'NT')")
   
    # Notification
    parser.add_argument("--webhook", help="Slack/Teams Webhook URL")

    args = parser.parse_args()

    # Handle NTLM Logic
    lmhash = ''
    nthash = ''
    password = args.password if args.password else ''
   
    if args.ntlm:
        if ':' in args.ntlm:
            lmhash, nthash = args.ntlm.split(':')
        else:
            nthash = args.ntlm
            lmhash = '00000000000000000000000000000000'

    # 1. Discovery
    dcs = get_domain_controllers(args.domain)
   
    print("\n{:<35} | {:<25}".format("Domain Controller", "Spooler Status"))
    print("-" * 65)

    vulnerable_list = []

    # 2. Audit
    for dc in dcs:
        status = check_spooler_status(dc, args.domain, args.username, password, lmhash, nthash)
       
        # Color coding for Console Output
        display_status = status
        if status == "RUNNING":
            display_status = f"\033[91m!! {status} !!\033[0m" # Red
            vulnerable_list.append({'hostname': dc, 'status': status})
        elif status == "ACCESS_DENIED":
            display_status = f"\033[93m{status}\033[0m"       # Yellow
        elif status == "STOPPED":
             display_status = f"\033[92m{status}\033[0m"      # Green

        print("{:<35} | {:<25}".format(dc, display_status))

    print("-" * 65)

    # 3. Notification
    if vulnerable_list:
        print(f"\n[!] Found {len(vulnerable_list)} DC(s) with Spooler RUNNING.")
        if args.webhook:
            send_webhook_alert(args.webhook, vulnerable_list, args.domain)
        else:
            print("[*] No webhook provided. Skipping alert.")
    else:
        print("\n[*] Compliance Check Passed: No Spoolers Running.")

if __name__ == "__main__":
    main()
