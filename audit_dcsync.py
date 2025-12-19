import sys
import argparse
import logging
from getpass import getpass

try:
    from ldap3 import Server, Connection, ALL, NTLM
    from ldap3.protocol.formatters.formatters import format_sid
except ImportError:
    print("[-] Critical Error: 'ldap3' library is missing.")
    print("    Please install it using: pip install ldap3")
    sys.exit(1)

# --------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# --------------------------------------------------------------------------
# DCSync Specific Extended Rights
DCSYNC_RIGHTS_GUIDS = {
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0db52e180b71': 'DS-Replication-Get-Changes-In-Filtered-Set'
}

# Critical Write Rights (For AdminSDHolder checks)
# 0x00040000 = WRITE_DACL (Ability to change permissions)
# 0x00080000 = WRITE_OWNER
# 0xF01FF = Full Control (approximate standard mask)
CRITICAL_WRITE_MASKS = [0x00040000, 0x00080000, 0x10000000]

# Well-known RIDs to filter out "Noise"
DEFAULT_PRIVILEGED_RIDS = ['-516', '-512', '-519', '-521', '-18'] # 18 is System

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# HELPERS
# --------------------------------------------------------------------------

def get_connection(domain, dc_ip, username, password):
    try:
        server = Server(dc_ip, get_info=ALL)
        full_user = f"{domain}\\{username}"
        conn = Connection(server, user=full_user, password=password, authentication=NTLM)
        if not conn.bind():
            logger.error(f"Bind failed: {conn.result}")
            return None
        return conn
    except Exception as e:
        logger.error(f"Connection error: {e}")
        return None

def resolve_sid_to_name(conn, sid, search_base):
    try:
        filter_str = f"(objectSid={sid})"
        conn.search(search_base=search_base, search_filter=filter_str, attributes=['sAMAccountName', 'cn'])
        if conn.entries:
            entry = conn.entries[0]
            return str(entry.sAMAccountName) if entry.sAMAccountName else str(entry.cn)
        return f"<Unknown Object: {sid}>"
    except Exception:
        return sid

def is_default_admin(sid):
    for rid in DEFAULT_PRIVILEGED_RIDS:
        if sid.endswith(rid):
            return True
    return False

# --------------------------------------------------------------------------
# ANALYSIS FUNCTIONS
# --------------------------------------------------------------------------

def parse_security_descriptor(conn, dn, check_type="DCSync"):
    """
    Generic parser for nTSecurityDescriptor.
    check_type: "DCSync" (checks GUIDs) or "Persistence" (checks Write/FullControl)
    """
    logger.info(f"Analyzing ACLs for: {dn}")
   
    try:
        conn.search(
            search_base=dn,
            search_filter='(objectClass=*)',
            attributes=['nTSecurityDescriptor'],
            controls=[('1.2.840.113556.1.4.801', True, b'\x07')] # SD_FLAGS
        )
    except Exception as e:
        logger.error(f"Failed to query object {dn}: {e}")
        return

    if not conn.entries:
        logger.error(f"Object not found: {dn}")
        return

    sd = conn.entries[0].nTSecurityDescriptor
    if not sd or not sd.dacl:
        logger.info("No DACL found.")
        return

    print(f"\n--- Report for: {dn} ---")
    print(f"{'TRUSTEE':<40} | {'PERMISSION / RIGHT':<40} | {'STATUS'}")
    print("-" * 100)

    findings = 0

    for ace in sd.dacl.aces:
        if ace['AceType'] not in ['ACCESS_ALLOWED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE']:
            continue

        trustee_sid = ace['Sid']
        risk_label = None
        permission_name = None

        # 1. Check for DCSync GUIDs (The original request)
        object_type = ace.get('ObjectType')
        if object_type and str(object_type).lower() in DCSYNC_RIGHTS_GUIDS:
            permission_name = DCSYNC_RIGHTS_GUIDS[str(object_type).lower()]
            risk_label = "DCSync Right"

        # 2. If checking AdminSDHolder, we also check for Write DACL (Persistence)
        if check_type == "Persistence":
            mask = ace['AceFlags'].get('value', 0) if isinstance(ace['AceFlags'], dict) else ace['Mask']
            # Note: ldap3 parsing varies slightly by version, referencing Mask attribute directly usually safest
           
            # Use raw mask integer if available
            raw_mask = ace['Mask']
           
            # Check for WriteDACL (0x40000) or GenericAll (0x10000000)
            if (raw_mask & 0x00040000) or (raw_mask & 0x10000000):
                if not permission_name: # Don't double report if it matched GUID
                    permission_name = "WriteDacl / FullControl"
                    risk_label = "Persistence Risk"

        if risk_label:
            # Analyze Trustworthiness
            status = " [!] ALERT"
            if is_default_admin(trustee_sid):
                status = " [OK] Default"

            # Resolve Name
            # We use the Domain Root for resolution context usually,
            # but here we can just use the passed DN's root context roughly.
            # Ideally we pass root_dn, but this is usually sufficient.
            trustee_name = resolve_sid_to_name(conn, trustee_sid, dn.split(',', 1)[1])

            print(f"{trustee_name[:38]:<40} | {permission_name[:38]:<40} |{status}")
            findings += 1

    if findings == 0:
        print("No high-risk entries found.")
    print("-" * 100)

# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Audit AD for DCSync & AdminSDHolder Persistence.")
    parser.add_argument("-d", "--domain", required=True, help="Target FQDN")
    parser.add_argument("-t", "--target-ip", required=True, help="DC IP Address")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", help="Password", default=None)
    args = parser.parse_args()

    password = args.password or getpass(f"[?] Password for {args.username}: ")

    conn = get_connection(args.domain, args.target_ip, args.username, password)

    if conn:
        logger.info("Connected. Locating roots...")
       
        try:
            # 1. Get Domain Root DN
            conn.search(search_base='', search_filter='(objectClass=*)', attributes=['defaultNamingContext'])
            root_dn = str(conn.entries[0].defaultNamingContext)
           
            # 2. Construct AdminSDHolder DN
            # It is always located at CN=AdminSDHolder,CN=System,{RootDN}
            adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{root_dn}"

            # 3. Audit Domain Root (The classic DCSync vulnerability)
            parse_security_descriptor(conn, root_dn, check_type="DCSync")

            # 4. Audit AdminSDHolder (The Persistence vulnerability)
            print("\n[+] Checking AdminSDHolder for Backdoors...")
            parse_security_descriptor(conn, adminsdholder_dn, check_type="Persistence")

        except Exception as e:
            logger.error(f"Audit aborted: {e}")
        finally:
            conn.unbind()

if __name__ == "__main__":
    main()
