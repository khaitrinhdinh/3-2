"""
Author: Trịnh Đình Khải - Re-implementation
Interactive chat mode for SMC client
"""

import sys
import time
import threading
from client_smc import ClientSMC


def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_info(msg):
    """Print info message"""
    print(f"[ℹ] {msg}")


def print_success(msg):
    """Print success message"""
    print(f"[✓] {msg}")


def print_error(msg):
    """Print error message"""
    print(f"[✗] {msg}")


def print_warning(msg):
    """Print warning message"""
    print(f"[⚠] {msg}")


def setup_client(user_id, server_url):
    """
    Setup client and perform authentication flow
    
    Returns:
        ClientSMC object if successful, None otherwise
    """
    print_header("SMC Client - Interactive Mode Setup")
    
    print(f"\nConfiguration:")
    print(f"  User ID:     {user_id}")
    print(f"  Server URL:  {server_url}")
    
    # Initialize client
    print_header("Initializing Client")
    client = ClientSMC(user_id, server_url)
    print_success(f"Client initialized (State: {client.state})")
    
    # Phase 1: Authenticate
    print_header("Authentication")
    if not client.authenticate():
        print_error("Authentication failed")
        return None
    print_success("Authenticated successfully")
    time.sleep(1)
    
    # Phase 2: Key Exchange
    print_header("Key Exchange (ECDH P-192)")
    if not client.key_exchange():
        print_error("Key exchange failed")
        return None
    print_success("Key exchange completed")
    time.sleep(1)
    
    # Phase 3: Establish Session
    print_header("Session Establishment")
    if not client.establish_session():
        print_error("Session establishment failed")
        return None
    print_success("Session established - Ready for secure messaging")
    
    return client


def poll_background(client, interval=3):
    """
    Background polling thread to check for new messages
    
    Args:
        client: ClientSMC instance
        interval: Polling interval in seconds
    """
    while True:
        try:
            time.sleep(interval)
            messages = client.poll_messages()
            if messages:
                for msg in messages:
                    print(f"\n[📩 Server] {msg}")
                    print("You: ", end="", flush=True)
        except Exception as e:
            # Silently handle errors in background thread
            pass


def show_help():
    """Display help message"""
    print("\n" + "=" * 70)
    print("  Available Commands")
    print("=" * 70)
    print("  /help          - Show this help message")
    print("  /status        - Show client status and connection info")
    print("  /poll          - Manually poll for new messages")
    print("  /exit          - Exit interactive mode")
    print("  /quit          - Same as /exit")
    print("\n  Just type your message and press Enter to send.")
    print("  Messages are automatically encrypted and sent securely.")
    print("=" * 70 + "\n")


def show_status(client):
    """Display client status"""
    print("\n" + "=" * 70)
    print("  Client Status")
    print("=" * 70)
    print(f"  State:              {client.state}")
    print(f"  User ID:            {client.user_id}")
    print(f"  Server URL:         {client.server_url}")
    print(f"  Session Key:        {'✓ Set' if client.session_key else '✗ Not set'}")
    print(f"  Last Message ID:    {client.last_message_id}")
    print("=" * 70 + "\n")


def interactive_mode(client):
    """
    Interactive chat mode
    
    Args:
        client: ClientSMC instance (must be in SESSION_ESTABLISHED state)
    """
    if client.state != "SESSION_ESTABLISHED":
        print_error(f"Cannot start interactive mode. Client state: {client.state}")
        print_info("Please ensure authentication, key exchange, and session establishment completed.")
        return
    
    print_header("Interactive Secure Chat Mode")
    print_success("Connected! You can now send secure messages.")
    print_info("Type '/help' for available commands")
    print_info("Type '/exit' to quit\n")
    
    # Start background polling thread
    poll_thread = threading.Thread(target=poll_background, args=(client,), daemon=True)
    poll_thread.start()
    print_info("Background message polling started (every 3 seconds)")
    
    print("\n" + "-" * 70)
    
    try:
        while True:
            try:
                # Get user input
                user_input = input("\nYou: ").strip()
                
                # Handle empty input
                if not user_input:
                    continue
                
                # Handle commands
                if user_input.startswith('/'):
                    command = user_input.lower()
                    
                    if command in ['/exit', '/quit']:
                        print_info("Exiting interactive mode...")
                        break
                    
                    elif command == '/help':
                        show_help()
                        continue
                    
                    elif command == '/status':
                        show_status(client)
                        continue
                    
                    elif command == '/poll':
                        print_info("Polling for messages...")
                        messages = client.poll_messages()
                        if messages:
                            print_success(f"Received {len(messages)} message(s):")
                            for i, msg in enumerate(messages, 1):
                                print(f"  {i}. {msg}")
                        else:
                            print_info("No new messages")
                        continue
                    
                    else:
                        print_warning(f"Unknown command: {user_input}")
                        print_info("Type '/help' for available commands")
                        continue
                
                # Send message
                print_info(f"Sending: '{user_input}'")
                success, msg_id, decrypted = client.send_message(user_input)
                
                if success:
                    print_success(f"Message sent successfully (ID: {msg_id})")
                    if decrypted:
                        print_success("Server response decrypted successfully")
                else:
                    print_error("Failed to send message")
                
            except KeyboardInterrupt:
                print("\n\n[!] Interrupted by user (Ctrl+C)")
                break
            except EOFError:
                print("\n\n[!] EOF detected, exiting...")
                break
            except Exception as e:
                print_error(f"Error: {e}")
                import traceback
                traceback.print_exc()
    
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
    
    print_header("Interactive Mode Ended")
    print_info("Thank you for using SMC Client!")


def main():
    """Main entry point"""
    # Configuration
    USER_ID = "group-1"
    SERVER_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"
    
    # You can also get these from command line arguments
    if len(sys.argv) >= 2:
        USER_ID = sys.argv[1]
    if len(sys.argv) >= 3:
        SERVER_URL = sys.argv[2]
    
    try:
        client = setup_client(USER_ID, SERVER_URL)
        
        if client is None:
            print_error("Failed to setup client. Exiting.")
            return False
        
        interactive_mode(client)
        
        return True
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        return False
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)

