#!/usr/bin/python3

import sqlite3
import subprocess
import re
import threading
import time
import subprocess
import sys
import requests
import random
from queue import Queue

class DatabaseManager:
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

class NetworkManager:
    def __init__(self):
        self.hosts = self.get_hosts()
        self.host_ip_dict = {}
        self.ip_host_dict = {}

    def get_hosts(self):
        output = subprocess.check_output("ps aux | grep 'mininet:'", shell=True).decode()
        return re.findall(r'mininet:(h\d+)', output)

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

class SimulationCore:
    def __init__(self, db_manager, network_manager, ping_interval=5, duration=300):
        self.db_manager = db_manager
        self.network_manager = network_manager
        self.ping_interval = ping_interval
        self.duration = duration
        self.results = {}
        self.failure_start_times = {}
        self.flow_recovery_times = {}

    def select_flows(self):
        flows = self.db_manager.get_flows()
        return random.sample(flows, random.randint(1, len(flows)))

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

    def continuous_ping_flow(self, flow_id, flow_src, flow_dst):
        end_time = time.time() + self.duration
        src_host = self.network_manager.ip_host_dict[flow_src]
        while time.time() < end_time:
            try:
                subprocess.run(f"sudo mnexec -a {self.network_manager.get_pid(src_host)} ping -c 1 -W 1 {flow_dst}", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.results[flow_id].put(1)
                if flow_id in self.failure_start_times:
                    recovery_time = time.time() - self.failure_start_times[flow_id]
                    if flow_id not in self.flow_recovery_times:
                        self.flow_recovery_times[flow_id] = []
                    self.flow_recovery_times[flow_id].append(recovery_time)
                    del self.failure_start_times[flow_id]
            except:
                self.results[flow_id].put(0)
                if flow_id not in self.failure_start_times:
                    self.failure_start_times[flow_id] = time.time()
            time.sleep(self.ping_interval)

    def simulate_vnf_failure(self, start_time):
        def _simulate_vnf_failure(start_time):
            while time.time() < start_time + self.duration:
                failed_host = random.choice(self.network_manager.hosts)
                print(f"\nSimulating failure on {failed_host}")
                subprocess.run(f"sudo mnexec -a {self.network_manager.get_pid(failed_host)} ifconfig {failed_host}-eth0 down", shell=True)
                time.sleep(random.randint(10, 15))
                print(f"\nRecovering {failed_host}")
                subprocess.run(f"sudo mnexec -a {self.network_manager.get_pid(failed_host)} ifconfig {failed_host}-eth0 up", shell=True)
                time.sleep(random.randint(10, 15))

        failure_thread = threading.Thread(target=_simulate_vnf_failure, args=(start_time,))
        failure_thread.start()
        return failure_thread

    def report_reliability(self, selected_flows):
        total_attempts = 0
        total_successes = 0
        total_recovery_time = 0
        recovery_attempts = 0

        for flow in selected_flows:
            flow_id = flow['id']
            attempts = self.results[flow_id].qsize()
            successes = sum(1 for _ in range(attempts) if self.results[flow_id].get() == 1)
            total_attempts += attempts
            total_successes += successes

            print(f"Flow {flow_id} had {successes}/{attempts} successful pings.")

            if flow_id in self.flow_recovery_times:
                recovery_times = self.flow_recovery_times[flow_id]
                average_recovery_time = sum(recovery_times) / len(recovery_times)
                print(f"Flow {flow_id} average recovery time: {average_recovery_time:.2f} seconds")
                total_recovery_time += sum(recovery_times)
                recovery_attempts += len(recovery_times)

        overall_reliability = (total_successes / total_attempts * 100) if total_attempts else 0
        overall_average_recovery = (total_recovery_time / recovery_attempts) if recovery_attempts else 0

        print(f"\nOverall network reliability: {overall_reliability:.2f}%")
        if recovery_attempts:
            print(f"Overall average recovery time: {overall_average_recovery:.2f} seconds")


    def print_status(self, start_time):
        elapsed_time = time.time() - start_time
        progress_percentage = min((elapsed_time / self.duration) * 100, 100)  # Cap at 100%

        print(f"\rSimulation progress: {progress_percentage:.2f}% completed, Elapsed Time: {elapsed_time:.2f}s", end="")
        if progress_percentage >= 100:
            print("\nSimulation complete. Preparing report...\n")
        sys.stdout.flush()



    def run_simulation(self):
        start_time = time.time()
        self.network_manager.get_host_ips()
        selected_flows = self.select_flows()
        self.results = {flow['id']: Queue() for flow in selected_flows}
        self.apply_flows(selected_flows)
        threads = [threading.Thread(target=self.continuous_ping_flow, args=(flow['id'], flow['src'], flow['dst'])) for flow in selected_flows]
        for t in threads:
            t.start()
        failure_thread = threading.Thread(target=self.simulate_vnf_failure, args=(start_time,))
        failure_thread.start()
        while any(t.is_alive() for t in threads):
            self.print_status(start_time)
            time.sleep(1)
        failure_thread.join()
        self.delete_flows(selected_flows)
        end_time = time.time()
        print(f"\n\nGenerating Report...")
        self.report_reliability(selected_flows)
        print(f"\n\nTotal simulation time: {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    db_path = '../nfv.sqlite'  # Adjust the path to your SQLite database file
    db_manager = DatabaseManager(db_path=db_path)
    network_manager = NetworkManager()

    simulation_duration = 300  # Duration of the simulation in seconds
    ping_interval = 2  # Interval between pings in seconds

    simulation_core = SimulationCore(db_manager=db_manager,
                                     network_manager=network_manager,
                                     ping_interval=ping_interval,
                                     duration=simulation_duration)
    
    simulation_core.run_simulation()
