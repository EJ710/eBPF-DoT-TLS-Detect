#!/usr/bin/env python3
import socket
import ssl
import json
import random
import sys
import os
import time
import signal

# Configuration
DATABASE_PATH = "/home/cicada3301/Desktop/deepdot/ja3me.json"
TEST_SERVER_IP = "127.0.0.1"
TEST_SERVER_PORT = 8443
MIN_INTERVAL = 60  # Minimum seconds between connections (1 minute)
MAX_INTERVAL = 150  # Maximum seconds between connections (2.5 minutes)

# Global flag to control the loop
running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C signal to exit gracefully"""
    global running
    print("\nCtrl+C detected. Exiting...")
    running = False

def load_all_ja3_fingerprints(database_path):
    """Load all JA3 fingerprints from the database"""
    try:
        if not os.path.exists(database_path):
            print(f"Database file not found: {database_path}")
            return None

        with open(database_path, 'r') as f:
            data = json.load(f)
        
        # Filter entries with valid JA3 strings
        valid_entries = [e for e in data if e.get("ja3") and len(e["ja3"]) > 10]
        
        if not valid_entries:
            print("No valid malicious JA3 entries found in database")
            return None
            
        print(f"Loaded {len(valid_entries)} malicious JA3 fingerprints")
        return valid_entries
    
    except Exception as e:
        print(f"Error loading database: {str(e)}")
        return None

def select_random_ja3(fingerprints):
    """Select a random JA3 fingerprint from the list"""
    entry = random.choice(fingerprints)
    print(f"Selected malicious JA3: {entry['ja3']}")
    print(f"First seen: {entry.get('first_seen', 'N/A')}")
    print(f"Digest: {entry.get('digest', 'N/A')}")
    print(f"Source: {entry.get('source', 'N/A')}")
    print("-" * 60)
    return entry["ja3"]

def attempt_connection(ja3_string):
    """Attempt a single malicious connection"""
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((TEST_SERVER_IP, TEST_SERVER_PORT))
        
        # Create SSL context with custom settings
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        
        # Set a common cipher suite for malicious JA3 fingerprints
        context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
        
        # Wrap socket
        ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
      
        # Send test request
        ssl_sock.sendall(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        response = ssl_sock.recv(1024)
        
        print("\n===== CONNECTION SUCCESSFUL =====")
        print(f"Received {len(response)} bytes")
        print("Server response header:")
        print(response.decode(errors="ignore").split("\r\n\r\n")[0])
        
        # Close connections
        ssl_sock.close()
        sock.close()
        
    except ConnectionRefusedError:
        print("\n===== CONNECTION FAILED =====")
        print("Error: Connection refused. Ensure a TLS server is running on localhost:8443")
        print("See instructions below to set up a test server.")
    except Exception as e:
        print("\n===== CONNECTION BLOCKED OR FAILED =====")
        print(f"Error: {str(e)}")
        print("This may indicate the connection was blocked or misconfigured.")

def simulate_attacks():
    """Main function to simulate malicious connections at random intervals"""
    print("\n===== Malicious TLS Connection Simulator =====")
    print(f"Using database: {DATABASE_PATH}")
    print(f"Target server: {TEST_SERVER_IP}:{TEST_SERVER_PORT}")
    print(f"Attack interval: {MIN_INTERVAL}-{MAX_INTERVAL} seconds")
    print("-" * 60)
    print("Press Ctrl+C to stop the simulator\n")
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Load all JA3 fingerprints once
    fingerprints = load_all_ja3_fingerprints(DATABASE_PATH)
    if not fingerprints:
        return
    
    attack_count = 0
    total_fingerprints = len(fingerprints)
    
    while running:
        attack_count += 1
        print(f"\n=== Preparing attack #{attack_count} ===")
        
        # Select random JA3 fingerprint from all available
        ja3_string = select_random_ja3(fingerprints)
        
        # Attempt connection
        attempt_connection(ja3_string)
        
        # Calculate next interval
        interval = random.randint(MIN_INTERVAL, MAX_INTERVAL)
        print(f"\nWaiting {interval} seconds before next attack...")
        
        # Wait for the interval, but check running flag periodically
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)
    
    print("\nSimulation stopped. Total attacks attempted:", attack_count - 1)
    print(f"Total unique fingerprints available: {total_fingerprints}")
    print("Check your tls_monitor output for detection details.")

if __name__ == "__main__":
    simulate_attacks()
