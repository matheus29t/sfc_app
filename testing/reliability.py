#!/usr/bin/python3

import requests
import subprocess
import random
import time
import threading
import re
import sqlite3
import sys
from queue import Queue

# Configuration
ping_interval = 5  # Interval between pings in seconds
duration = 300  # Duration of the simulation in seconds

def get_flows():
    conn = sqlite3.connect('../nfv.sqlite')  # Adjust the path to your database file
    cursor = conn.cursor()
    try:
        # Updated query to include ipv4_src and ipv4_dst fields
        cursor.execute("SELECT id, ipv4_src, ipv4_dst FROM flows")
        flows_info = [{'id': row[0], 'src': row[1], 'dst': row[2]} for row in cursor.fetchall()]
        return flows_info
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def get_hosts():
    # Use subprocess to execute the command and decode the byte string
    output = subprocess.check_output("ps aux | grep 'mininet:'", shell=True).decode()
    # Use regular expression to match host entries
    hosts = re.findall(r'mininet:(h\d+)', output)
    return hosts

flows = get_flows() # Available flows
hosts = get_hosts()  # Dynamically get the list of hosts
results = {}

failure_start_times = {}
flow_recovery_times = {}

host_ip_dict = {}
ip_host_dict = {}

def get_host_ips():
    for host in hosts:
        pid = get_pid(host)  # Assuming a function to get PID by host name
        if pid:
            ip = get_primary_ip(host)  # Assuming it returns the primary non-localhost IP
            host_ip_dict[host] = ip
            ip_host_dict[ip] = host

def select_flows():
    return random.sample(flows, random.randint(1, len(flows)))

def apply_flows(selected_flows):
    base_url = 'http://127.0.0.1:8080/add_flow/'
    for flow in selected_flows:
        try:
            response = requests.get(f"{base_url}{flow['id']}")
            if response.status_code == 200:
                print(f"\nApplied flow {flow['id']} ({flow['src']} -> {flow['dst']})")
            else:
                print(f"\nError applying flow {flow['id']}")
        except Exception as e:
            print(f"\nFailed to apply flow {flow['id']}: {e}")

def delete_flows(selected_flows):
    base_url = 'http://127.0.0.1:8080/delete_flow/'
    for flow in selected_flows:
        try:
            response = requests.get(f"{base_url}{flow['id']}")
            if response.status_code == 200:
                print(f"\nDeleted flow {flow['id']}")
            else:
                print(f"\nError deleting flow {flow['id']}")
        except Exception as e:
            print(f"\nFailed to delete flow {flow['id']}: {e}")

def get_pid(host):
    try:
        return subprocess.check_output(f"pgrep -f 'mininet:{host}'", shell=True).decode().splitlines()[0]
    except Exception:
        return None

def get_primary_ip(host):
    pid = get_pid(host)
    if pid:
        try:
            output = subprocess.check_output(f"sudo mnexec -a {pid} ifconfig", shell=True).decode()
            ip = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', output)
            return [x for x in ip if x != '127.0.0.1'][0]
        except Exception:
            return None
    return None
    
def continuous_ping_flow(flow_id, flow_src, flow_dst):
    global failure_start_times, flow_recovery_times
    end_time = time.time() + duration
    src_host = ip_host_dict[flow_src]
    while time.time() < end_time:
        try:
            subprocess.run(f"sudo mnexec -a {get_pid(src_host)} ping -c 1 -W 1 {flow_dst}", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            results[flow_id].put(1)
            # If previously failed, calculate recovery time
            if flow_id in failure_start_times:
                recovery_time = time.time() - failure_start_times[flow_id]
                if flow_id not in flow_recovery_times:
                    flow_recovery_times[flow_id] = []
                flow_recovery_times[flow_id].append(recovery_time)
                del failure_start_times[flow_id]
        except:
            results[flow_id].put(0)
            # Mark the start of a failure if not already failed
            if flow_id not in failure_start_times:
                failure_start_times[flow_id] = time.time()
    time.sleep(ping_interval)

def simulate_vnf_failure():
    def _simulate_vnf_failure():
        while time.time() < start_time + duration:
            failed_host = random.choice(hosts)
            print(f"\nSimulating failure on {failed_host}")  # New line to ensure visibility of this event
            subprocess.run(f"sudo mnexec -a {get_pid(failed_host)} ifconfig {failed_host}-eth0 down", shell=True)
            time.sleep(random.randint(5, 15))  # Random downtime
            print(f"\nRecovering {failed_host}")  # New line for recovery event
            subprocess.run(f"sudo mnexec -a {get_pid(failed_host)} ifconfig {failed_host}-eth0 up", shell=True)
            time.sleep(random.randint(5, 15))  # Random recovery time

    failure_thread = threading.Thread(target=_simulate_vnf_failure)
    failure_thread.start()
    return failure_thread

# Report reliability for flows and overall network
def report_reliability(selected_flows):
    total_attempts = 0
    total_successes = 0
    total_recovery_time = 0
    recovery_count = 0

    for flow in selected_flows:
        flow_id = flow['id']
        attempts = results[flow_id].qsize()
        successes = sum(1 for _ in range(attempts) if results[flow_id].get() == 1)
        total_attempts += attempts
        total_successes += successes

        if attempts == 0:
            print(f"Flow {flow_id} had no ping attempts, reliability cannot be calculated.")
        else:
            reliability = successes / attempts * 100
            print(f"Flow {flow_id} reliability: {reliability:.2f}%")
            
            if flow_id in flow_recovery_times and flow_recovery_times[flow_id]:
                average_recovery_time = sum(flow_recovery_times[flow_id]) / len(flow_recovery_times[flow_id])
                print(f"Flow {flow_id} average recovery time: {average_recovery_time:.2f} seconds")
                total_recovery_time += sum(flow_recovery_times[flow_id])
                recovery_count += len(flow_recovery_times[flow_id])

    # Calculate overall reliability
    if total_attempts > 0:
        overall_reliability = total_successes / total_attempts * 100
        print(f"\nOverall network reliability: {overall_reliability:.2f}%")
    else:
        print("\nNo ping attempts were made, overall network reliability cannot be calculated.")

    # Calculate overall average recovery time for flows that recovered
    if recovery_count > 0:
        overall_average_recovery_time = total_recovery_time / recovery_count
        print(f"\nOverall flow recovery time: {overall_average_recovery_time:.2f} seconds")
    else:
        print("\nNo recovery times were recorded, overall average flow recovery time cannot be calculated.")

def print_status(start_time, duration):
    elapsed_time = time.time() - start_time
    progress_percentage = (elapsed_time / duration) * 100
    sys.stdout.write(f'\rSimulation progress: {progress_percentage:.2f}% completed ')
    sys.stdout.flush()

if __name__ == '__main__':
    start_time = time.time()
    get_host_ips()
    selected_flows = select_flows()
    results = {flow['id']: Queue() for flow in selected_flows}
    apply_flows(selected_flows)
    threads = [threading.Thread(target=continuous_ping_flow, args=(flow['id'], flow['src'], flow['dst'])) for flow in selected_flows]
    for t in threads:
        t.start()
    failure_thread = simulate_vnf_failure()
    while any(t.is_alive() for t in threads):
        print_status(start_time, duration)
        time.sleep(1)
    failure_thread.join()
    delete_flows(selected_flows)
    end_time = time.time()
    print(f"\n\nGenerating Report...")
    report_reliability(selected_flows)
    print(f"\n\nTotal simulation time: {end_time - start_time:.2f} seconds")