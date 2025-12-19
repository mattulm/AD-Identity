import sys
import argparse
import getpass
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

# Mapping AD 'msDFSR-Flags' integer values to their migration states.
# Source: MS-ADTS (Active Directory Technical Specification)
MIGRATION_STATES = {
    0: "Start (FRS in use)",
    1: "Prepared (FRS in use, DFSR initiated)",
    2: "Redirected (DFSR in use, FRS background)",
    3: "Eliminated (DFSR in use, FRS removed)"
}

def get_domain_dn(domain_name):
    """
    Helper to convert a standard domain string (example.com)
    into a Distinguished Name (DC=example,DC=com).
   
    Args:
        domain_name (str): The FQDN of the domain.
       
    Returns:
        str: The Distinguished Name (DN).
    """
    return ','.join([f"DC={part}" for part in domain_name.split('.')])

def get_sysvol_migration_state(server_address, domain, username, password):
    """
    Connects to the Domain Controller via LDAP and queries the
    msDFSR-GlobalSettings object to determine the replication state.
   
    Security Note:
    This function uses NTLM for simplicity in this snippet, but for
    production environments, consider using Kerberos or LDAPS (SSL)
    to prevent credential interception.
    """
   
    # Fail fast if inputs are empty
    if not all([server_address, domain, username, password]):
        print("[-] Error: Missing connection credentials.")
        return None

    try:
        # Create Server object. get_info=ALL fetches schema info automatically.
        server = Server(server_address, get_info=ALL)
       
        # Format user as DOMAIN\User for NTLM
        user_dn = f"{domain}\\{username}"
       
        print(f"[*] Connecting to {server_address} as {user_dn}...")
       
        # Establish connection
        conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)
       
        if not conn.bound:
            print("[-] Authentication failed.")
            return None
       
        print("[+] Connection established.")

        # Construct the search base for the Global Settings
        domain_dn = get_domain_dn(domain)
        search_base = f"CN=ms-DFSR-GlobalSettings,CN=System,{domain_dn}"
       
        # Filter: We are looking strictly for the settings object
        search_filter = "(objectClass=msDFSR-GlobalSettings)"
       
        # Attributes: We only care about msDFSR-Flags
        print(f"[*] Querying object: {search_base}")
       
        conn.search(search_base=search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['msDFSR-Flags'])

        if not conn.entries:
            # If the object doesn't exist, it usually implies the domain
            # is too old to know about DFSR, or permissions are denied.
            print("[-] Object not found. The domain might be purely FRS (Pre-2008 mode) or access is denied.")
            return "FRS_LEGACY"

        # Parse the result
        entry = conn.entries[0]
        flag_val = entry['msDFSR-Flags'].value

        # Handle cases where the attribute might be unset (None)
        if flag_val is None:
            print("[-] msDFSR-Flags attribute is empty. State unknown.")
            return "Unknown"

        state_str = MIGRATION_STATES.get(flag_val, f"Unknown State ID: {flag_val}")
       
        print(f"\n✅ Replication State Found: {flag_val}")
        print(f"➡  Status: {state_str}")
       
        return state_str

    except LDAPException as e:
        print(f"[-] LDAP Error: {e}")
        return "Error"
    except Exception as e:
        print(f"[-] General Error: {e}")
        return "Error"
    finally:
        # Ensure we close the connection to be a good network citizen
        if 'conn' in locals() and conn.bound:
            conn.unbind()

def main():
    """
    Main entry point.
    Parses arguments and initiates the check.
    """
    parser = argparse.ArgumentParser(
        description="Check SYSVOL Replication State (FRS vs DFSR) via LDAP.",
        epilog="Example: python check_dfsr.py -d example.com -u administrator -s dc01.example.com"
    )
   
    parser.add_argument('-d', '--domain', required=True, help="Target Domain (e.g., example.com)")
    parser.add_argument('-s', '--server', required=True, help="IP or Hostname of a Domain Controller")
    parser.add_argument('-u', '--user', required=True, help="Username (without domain prefix)")
    parser.add_argument('-p', '--password', help="Password (optional, will prompt if omitted)")

    args = parser.parse_args()

    # Security: Never rely on CLI args for passwords in shared history environments.
    # We allow it for automation (-p), but prefer interactive prompt.
    password = args.password
    if not password:
        password = getpass.getpass(prompt=f"Enter password for {args.domain}\\{args.user}: ")

    get_sysvol_migration_state(args.server, args.domain, args.user, password)

if __name__ == "__main__":
    main()
