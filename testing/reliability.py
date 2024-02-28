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
duration = 100  # Duration of the simulation in seconds

def get_flows():
    conn = sqlite3.connect('../nfv.sqlite') # Database path
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM flows")
        flow_ids = [row[0] for row in cursor.fetchall()]
        return flow_ids
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
results = {host: Queue() for host in hosts}  # Initialize results storage

def select_flows():
    return random.sample(flows, random.randint(1, len(flows)))

def apply_flows(selected_flows):
    base_url = 'http://127.0.0.1:8080/add_flow/'
    for flow_id in selected_flows:
        try:
            response = requests.get(f'{base_url}{flow_id}')
            print(f'\nApplied flow {flow_id}' if response.status_code == 200 else f'\nError applying flow {flow_id}')
        except Exception as e:
            print(f'\nFailed to apply flow {flow_id}: {e}')

def delete_flows(selected_flows):
    base_url = 'http://127.0.0.1:8080/delete_flow/'
    for flow_id in selected_flows:
        try:
            response = requests.get(f'{base_url}{flow_id}')
            print(f'\nDeleted flow {flow_id}' if response.status_code == 200 else f'\nError deleting flow {flow_id}')
        except Exception as e:
            print(f'\nFailed to delete flow {flow_id}: {e}')

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

def continuous_ping(host):
    ip = get_primary_ip(host)
    if ip:
        end_time = start_time + duration
        while time.time() < end_time:
            try:
                subprocess.run(f"sudo mnexec -a {get_pid('h1')} ping -c 1 -W 1 {ip}", shell=True, check=True, stdout=subprocess.DEVNULL)
                results[host].put(1)
            except subprocess.CalledProcessError:
                results[host].put(0)
            time.sleep(ping_interval)
    else:
        print(f'\nCould not get IP for {host}')

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

def report_reliability():
    print('\n\nFinal Reliability Report:')
    total_successful_pings = 0
    total_attempts = len(hosts) * int(duration / ping_interval)
    for host in hosts:
        successful = sum([results[host].get() for _ in range(results[host].qsize())])
        total_successful_pings += successful
        print(f'{host}: {successful}/{int(duration / ping_interval)} successful pings, Reliability: {100 * successful / int(duration / ping_interval):.2f}%')
    
    overall_reliability = (total_successful_pings / total_attempts) * 100
    print(f'\nOverall network reliability: {overall_reliability:.2f}%')
    sys.stdout.flush()

def print_status(start_time, duration):
    elapsed_time = time.time() - start_time
    progress_percentage = (elapsed_time / duration) * 100
    sys.stdout.write(f'\rSimulation progress: {progress_percentage:.2f}% completed ')
    sys.stdout.flush()

if __name__ == '__main__':
    start_time = time.time()
    selected_flows = select_flows()
    apply_flows(selected_flows)
    threads = [threading.Thread(target=continuous_ping, args=(host,)) for host in hosts]
    for t in threads:
        t.start()
    failure_thread = simulate_vnf_failure()
    while any(t.is_alive() for t in threads):
        print_status(start_time, duration)
        time.sleep(1)
    failure_thread.join()
    delete_flows(selected_flows)
    end_time = time.time()
    report_reliability()
    print(f"\n\nTotal simulation time: {end_time - start_time:.2f} seconds")