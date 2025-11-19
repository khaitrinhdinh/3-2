"""
Author: Trịnh Đình Khải - Re-implementation
Main entry point for SMC client testing
"""

import sys
import time
from client_smc import ClientSMC


def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    """Main flow"""
    print_header("SMC Client Re-implementation - Phase 4 Test")
    
    # ========================================================================
    # Configuration
    # ========================================================================
    USER_ID = "group-1"
    SERVER_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"
    
    print(f"\nConfiguration:")
    print(f"  User ID:     {USER_ID}")
    print(f"  Server URL:  {SERVER_URL}")
    
    # ========================================================================
    # Initialize client
    # ========================================================================
    print_header("Phase 1: Initialize Client")
    # client = ClientSMC(USER_ID, SERVER_URL)

    USE_BURP = True  # Set True để dùng Burp
    PROXY_URL = "http://127.0.0.1:8080"  # Burp proxy URL
    client = ClientSMC(USER_ID, SERVER_URL, use_proxy=USE_BURP, proxy_url=PROXY_URL)

    print(f"[✓] Client initialized")
    print(f"    State: {client.state}")
    
    # ========================================================================
    # Phase 1: Authenticate
    # ========================================================================
    print_header("Phase 2: Authenticate")
    if not client.authenticate():
        print("\n[✗] FAILED: Authentication unsuccessful")
        return False
    
    time.sleep(1)  # Delay to avoid rate limiting
    
    # ========================================================================
    # Phase 2: Key Exchange
    # ========================================================================
    print_header("Phase 3: Key Exchange (ECDH P-192)")
    if not client.key_exchange():
        print("\n[✗] FAILED: Key exchange unsuccessful")
        return False
    
    time.sleep(1)
    
    # ========================================================================
    # Phase 3: Establish Session
    # ========================================================================
    print_header("Phase 4: Establish Session")
    if not client.establish_session():
        print("\n[✗] FAILED: Session establishment unsuccessful")
        return False
    
    time.sleep(1)
    
    # ========================================================================
    # Phase 4a: Send Test Messages
    # ========================================================================
    print_header("Phase 5a: Send Secure Messages")
    test_messages = [
        "Hello, Secure Chat!",
        "This is message 2",
        "Final test message"
    ]
    
    sent_count = 0
    decrypted_count = 0
    for msg in test_messages:
        success, msg_id, decrypted = client.send_message(msg)
        if success:
            sent_count += 1
            if decrypted:
                decrypted_count += 1
        time.sleep(2)  # Delay between messages
    
    if sent_count == 0:
        print(f"\n[⚠] WARNED: No messages sent successfully")
        # Don't return False - server might not support /message/send
    else:
        print(f"\n[✓] Sent {sent_count}/{len(test_messages)} messages successfully")
        if decrypted_count > 0:
            print(f"[✓] Attempted to decrypt {decrypted_count} server response(s)")
    
    # ========================================================================
    # Summary
    # ========================================================================
    print_header("Summary")
    print(f"\n[✓] Client State:           {client.state}")
    print(f"[✓] Messages Sent:          {sent_count}")
    
    if client.state == "SESSION_ESTABLISHED":
        print(f"\n[✓✓✓] FULL FLOW COMPLETED SUCCESSFULLY ✓✓✓")
        print(f"\nKey Metrics:")
        print(f"  - Authentication:      ✓")
        print(f"  - ECDH Key Exchange:   ✓")
        print(f"  - Session Derivation:  ✓")
        print(f"  - Message Encryption:  {'✓' if sent_count > 0 else '⚠'}")
        print(f"  - Response Decryption:  {'✓' if decrypted_count > 0 else '⚠'}")
        return True
    else:
        print(f"\n[✗] Flow incomplete - unexpected final state")
        return False


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[✗] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

