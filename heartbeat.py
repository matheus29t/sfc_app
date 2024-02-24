#!/usr/bin/env python3

import sys
import socket
import json
import time

def send_heartbeat(vnf_id, controller_addr, controller_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    heartbeat_message = json.dumps({"vnf_id": vnf_id}).encode()
    while True:
        try:
            s.sendto(heartbeat_message, (controller_addr, controller_port))
            print(f"Heartbeat sent for VNF {vnf_id} to {controller_addr}:{controller_port}")
        except Exception as e:
            print(f"Failed to send heartbeat for VNF {vnf_id}: {str(e)}")
        finally:
            time.sleep(5)  # Adjust the sleep time as needed

if __name__ == "__main__":
    vnf_id = sys.argv[1]
    controller_addr = sys.argv[2]
    controller_port = int(sys.argv[3])
    send_heartbeat(vnf_id, controller_addr, controller_port)
