import sys
import json
import base64
import os

try:
    from cryptography.fernet import Fernet
except ImportError:
    print(json.dumps({"error": "cryptography module not found. Please run: pip install cryptography"}), file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "generate":
            # Generate a key and a token for a sample message
            key = Fernet.generate_key()
            f = Fernet(key)
            message = b"Hello from Python!"
            token = f.encrypt(message)
            
            output = {
                "key": key.decode('utf-8'),
                "token": token.decode('utf-8'),
                "plaintext": message.decode('utf-8')
            }
            print(json.dumps(output))
            return

        if command == "decrypt":
            # Expecting JSON input from stdin: { "key": "...", "token": "..." }
            try:
                data = json.load(sys.stdin)
                key = data["key"].encode('utf-8')
                token = data["token"].encode('utf-8')
                
                f = Fernet(key)
                plaintext = f.decrypt(token)
                
                print(json.dumps({"plaintext": plaintext.decode('utf-8')}))
            except Exception as e:
                print(json.dumps({"error": str(e)}), file=sys.stderr)
                sys.exit(1)
            return

    # Default usage help
    print(json.dumps({"error": "Usage: python verify_compat.py [generate|decrypt]"}), file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    main()
