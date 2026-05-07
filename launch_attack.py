import requests
import json
import argparse
import sys
from time import sleep

def launch(attack_type, intensity):
    print(f"[*] Initializing RED TEAM Attack Vector...")
    print(f"    Target: http://127.0.0.1:8000/api/inject-attack")
    print(f"    Payload Type: {attack_type}")
    print(f"    Packet Volume: {intensity}\n")

    sleep(1) # Dramatic pause

    try:
        response = requests.post(
            "http://127.0.0.1:8000/api/inject-attack",
            json={"type": attack_type, "intensity": intensity}
        )
        
        if response.status_code == 200:
            data = response.json()
            if "error" in data:
                print(f"[-] Exploit failed: {data['error']}")
            else:
                print("[+] Target Server breached successfully!")
                print(f"    Result: {data.get('message')}")
                print(f"    Attack Queue Size: {data.get('queue_size')}")
        else:
            print(f"[-] Exploit failed. Target returned HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[-] Exploit failed. Is the SENTRi-X Dashboard offline?")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Hybrid Red-Team Injection Script for SENTRi-X")
    parser.add_argument("--type", help="Name of the attack to simulate on the Dashboard (e.g. 'DDoS', 'Heartbleed')", default="Web Attack (SQLi)")
    parser.add_argument("--intensity", type=int, help="Number of malicious packets to blast into the data stream", default=10)
    
    args = parser.parse_args()
    
    launch(args.type, args.intensity)