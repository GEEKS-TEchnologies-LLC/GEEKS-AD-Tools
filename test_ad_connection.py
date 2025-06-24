#!/usr/bin/env python3
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError

def test_connection(server, bind_user, password, base_dn):
    """Test AD connection with given credentials"""
    try:
        server_uri = f"ldap://{server}"
        server_obj = ldap3.Server(server_uri, get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server_obj, 
            user=bind_user, 
            password=password, 
            auto_bind=True, 
            raise_exceptions=True
        )
        print(f"✅ SUCCESS with: {bind_user}")
        conn.unbind()
        return True
    except LDAPBindError as e:
        print(f"❌ FAILED with: {bind_user}")
        print(f"   Error: {e}")
        return False
    except Exception as e:
        print(f"❌ ERROR with: {bind_user}")
        print(f"   Error: {e}")
        return False

def main():
    server = "192.168.1.59"
    password = "T@ch0n!"
    base_dn = "DC=sunray,DC=internal"
    
    # Test different Bind DN formats
    test_cases = [
        "CN=Administrator,CN=Users,DC=sunray,DC=internal",  # Current format
        "Administrator@sunray.internal",                    # UPN format
        "sunray.internal\\Administrator",                   # Domain\Username format
        "CN=Administrator,DC=sunray,DC=internal",           # Without Users container
        "Administrator",                                    # Just username
    ]
    
    print("Testing AD connection with different credential formats...")
    print("=" * 60)
    
    success = False
    for bind_user in test_cases:
        if test_connection(server, bind_user, password, base_dn):
            success = True
            print(f"\n🎉 Working configuration found!")
            print(f"   Server: {server}")
            print(f"   Bind User: {bind_user}")
            print(f"   Base DN: {base_dn}")
            break
        print()
    
    if not success:
        print("\n❌ All connection attempts failed.")
        print("\nPossible solutions:")
        print("1. Check if the password is correct")
        print("2. Verify the Administrator account is not disabled/locked")
        print("3. Ensure the account has proper permissions")
        print("4. Try using a different admin account")

if __name__ == "__main__":
    main() 