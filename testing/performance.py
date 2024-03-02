#!/usr/bin/python3

import sqlite3
import subprocess
import re
import threading
import time
import requests
import random
import sys
import iperf3
from queue import Queue

class PerformanceDatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_flows(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, ipv4_src, ipv4_dst FROM flows")
            flows_info = [{'id': row[0], 'src': row[1], 'dst': row[2]} for row in cursor.fetchall()]
            return flows_info
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

class PerformanceNetworkManager:
    def __init__(self):
        self.hosts = self.get_hosts()
        self.host_ip_dict = {}
        self.ip_host_dict = {}

    def get_hosts(self):
        output = subprocess.check_output("ps aux | grep 'mininet:'", shell=True).decode()
        hosts = re.findall(r'mininet:(h\d+)', output)
        return hosts

    def get_host_ips(self):
        for host in self.hosts:
            ip = self.get_primary_ip(host)
            if ip:
                self.host_ip_dict[host] = ip
                self.ip_host_dict[ip] = host

    def get_pid(self, host):
        try:
            return subprocess.check_output(f"pgrep -f 'mininet:{host}'", shell=True).decode().splitlines()[0]
        except Exception:
            return None

    def get_primary_ip(self, host):
        pid = self.get_pid(host)
        if pid:
            try:
                output = subprocess.check_output(f"sudo mnexec -a {pid} ifconfig", shell=True).decode()
                ip = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', output)
                return [x for x in ip if x != '127.0.0.1'][0]
            except Exception:
                return None
        return None

class PerformanceSimulationCore:
    def __init__(self, db_manager, network_manager, latency_samples=10, throughput_samples=10):
        self.db_manager = db_manager
        self.network_manager = network_manager
        self.latency_samples = latency_samples
        self.throughput_samples = throughput_samples
        self.latency_results = {}
        self.throughput_results = {}
        self.total_measurements = 0
        self.completed_measurements = 0

    def select_flows(self):
        flows = self.db_manager.get_flows()
        return random.sample(flows, random.randint(1, 2)) #len(flows)))
    
    def apply_flows(self, selected_flows):
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

    def delete_flows(self, selected_flows):
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

    def measure_latency(self, flow_id, flow_src, flow_dst):
        latencies = []  # Store multiple measurements
        for _ in range(self.latency_samples):
            start_time = time.time()
            # Ping and return success/failure and RTT
            success, rtt = self.ping_host(self.network_manager.ip_host_dict.get(flow_src), flow_dst)
            end_time = time.time()
            self.completed_measurements += 1
            self.update_progress()
            if success:
                latencies.append(rtt)
            else:
                latencies.append(end_time - start_time)
            #time.sleep(1)  # Sleep between measurements if needed
        self.latency_results[flow_id] = sum(latencies) / len(latencies)  # Store average latency
    
    def ping_host(self, src_host, destination_ip):
        pid = self.network_manager.get_pid(src_host)
        if pid:
            try:
                # Constructing and executing the ping command with mnexec
                command = f"sudo mnexec -a {pid} ping -c 1 {destination_ip}"
                output = subprocess.check_output(command, shell=True, universal_newlines=True)
                
                # Extracting RTT using regular expression
                match = re.search(r'time=(\d+.\d+) ms', output)
                if match:
                    rtt = float(match.group(1))
                    return True, rtt  # Ping successful, return RTT
            except subprocess.CalledProcessError:
                pass  # Ping failed or command error
        
        return False, None
    
    def measure_throughput(self, flow):
        flow_id = flow['id']
        throughputs = []  # Store multiple measurements
        for _ in range(self.throughput_samples):
            throughput = self.run_iperf3_client(self.network_manager.ip_host_dict.get(flow['src']), flow['dst'])
            if throughput is not None:
                throughputs.append(throughput)
            #time.sleep(1)  # Sleep between measurements if needed
            self.completed_measurements += 1
            self.update_progress()
        if throughputs:
            self.throughput_results[flow_id] = sum(throughputs) / len(throughputs)  # Store average throughput
        else:
            print(f"Flow {flow_id}: Throughput measurement failed")

    def run_iperf3_client(self, src_host, flow_dst):
        try:
            cmd = f"sudo timeout 15 mnexec -a {self.network_manager.get_pid(src_host)} iperf3 -c {flow_dst} -p 8000"
            output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            # Updated regex to match the throughput in a more flexible manner
            match = re.search(r'([\d\.]+) Gbits/sec.*sender', output)
            if match:
                throughput_str = match.group(1)
                # Convert Gbits/sec to Mbps
                throughput = float(throughput_str.split()[0]) * 1000
                return throughput
        except subprocess.CalledProcessError as e:
            print(f"Error running iperf3 client") #: {e.output}")
        return 0  # Throughput measurement failed or regex didn't match

    def run_simulation(self):
        print("Starting simulation...")
        self.network_manager.get_host_ips()
        selected_flows = self.select_flows()

        self.total_measurements = (self.latency_samples + self.throughput_samples) * len(selected_flows)

        if not selected_flows:
            print("No flows selected for simulation. Exiting...")
            return
        
        # Applying flows
        print("Applying selected flows...")
        self.apply_flows(selected_flows)

        # Prepare for measurements
        latency_threads = []
        throughput_threads = []

        # Latency measurement
        print("\nMeasuring Latency...")
        for flow in selected_flows:
            t = threading.Thread(target=self.measure_latency, args=(flow['id'], flow['src'], flow['dst']))
            t.start()
            latency_threads.append(t)

        # Wait for latency measurements to complete
        for t in latency_threads:
            t.join()

        # Throughput measurement
        print("\nMeasuring Throughput...")
        for flow in selected_flows:
            t = threading.Thread(target=self.measure_throughput, args=(flow,)) #['id'], flow['src'], flow['dst']))
            t.start()
            throughput_threads.append(t)

        # Wait for throughput measurements to complete
        for t in throughput_threads:
            t.join()

        # Deleting flows
        print("\nCleaning up: Deleting applied flows...")
        self.delete_flows(selected_flows)

        # Reporting
        print("\nFinal Report:")
        self.report_results()

    def update_progress(self):
        # Calculate the percentage of completed measurements
        progress_percentage = (self.completed_measurements / self.total_measurements) * 100 if self.total_measurements else 0
        # Display the progress
        print(f"\rSimulation progress: {progress_percentage:.2f}% completed", end="")

    
    def report_results(self):
        print("Latency Results:")
        for flow_id, latency in self.latency_results.items():
            print(f"Flow {flow_id}: Latency = {latency:.3f} seconds")
        
        print("\nThroughput Results:")
        for flow_id, throughput in self.throughput_results.items():
            print(f"Flow {flow_id}: Throughput = {throughput} Mbps")

if __name__ == '__main__':
    db_path = '../nfv.sqlite'  # Adjust the path to your SQLite database file
    db_manager = PerformanceDatabaseManager(db_path=db_path)
    network_manager = PerformanceNetworkManager()

    latency_samples = 30
    throughput_samples = 5

    simulation_core = PerformanceSimulationCore(db_manager=db_manager,
                                                network_manager=network_manager,
                                                latency_samples=latency_samples,
                                                throughput_samples=throughput_samples)
    
    simulation_core.run_simulation()
