#!/usr/bin/python3

import subprocess
import numpy as np
import matplotlib.pyplot as plt
import re
import sys

def run_script(script_name):
    # Note: This won't capture real-time output to the console. Consider adapting if needed.
    result = subprocess.run(['python3', script_name], capture_output=True, text=True, check=True)
    return result.stdout

def initialize_plots():
    plt.ion()
    fig, axs = plt.subplots(2, 2, figsize=(12, 6))
    return fig, axs

def update_plots(axs, reliability_scores, recovery_times, latencies, throughputs):
    axs[0, 0].cla()
    axs[0, 1].cla()
    axs[1, 0].cla()
    axs[1, 1].cla()

    axs[0, 0].hist(reliability_scores, bins=5, color='skyblue')
    axs[0, 0].set_title('Network Reliability (%)')

    axs[0, 1].hist(recovery_times, bins=5, color='orange')
    axs[0, 1].set_title('Average Recovery Time (seconds)')

    axs[1, 0].boxplot(latencies)
    axs[1, 0].set_title('Latencies (seconds)')

    axs[1, 1].boxplot(throughputs)
    axs[1, 1].set_title('Throughputs (Mbps)')

    plt.pause(0.1)

def parse_reliability_output(output):
    reliability_match = re.search(r"Overall network reliability: (\d+\.\d+)%", output)
    recovery_time_match = re.search(r"Overall average recovery time: (\d+\.\d+) seconds", output)
    
    reliability = float(reliability_match.group(1)) if reliability_match else None
    recovery_time = float(recovery_time_match.group(1)) if recovery_time_match else None
    
    return reliability, recovery_time

def parse_performance_output(output):
    latencies = re.findall(r"Flow \d+: Latency = (\d+\.\d+) seconds", output)
    throughputs = re.findall(r"Flow \d+: Throughput = (\d+\.\d+) Mbps", output)
    
    latencies = [float(lat) for lat in latencies]
    throughputs = [float(throughput) for throughput in throughputs]
    
    return latencies, throughputs

def measure_and_plot(reliability_iterations=10, performance_iterations=30):
    reliability_scores = []
    recovery_times = []
    latencies = []
    throughputs = []

    fig, axs = initialize_plots()

    for cur in range(max(reliability_iterations, performance_iterations)):
        if cur < reliability_iterations:
            reliability_output = run_script('reliability.py')
            reliability, recovery_time = parse_reliability_output(reliability_output)
            if reliability is not None:
                reliability_scores.append(reliability)
            if recovery_time is not None:
                recovery_times.append(recovery_time)
            print(f'\rReliability check {cur+1}/{reliability_iterations} - {(cur+1)/reliability_iterations * 100}%')
            update_plots(axs, reliability_scores, recovery_times, latencies, throughputs)

        if cur < performance_iterations:
            performance_output = run_script('performance.py')
            latency, throughput = parse_performance_output(performance_output)
            latencies.extend(latency)
            throughputs.extend(throughput)
            print(f'\rPerformance check {cur+1}/{performance_iterations} - {(cur+1)/performance_iterations * 100}%')
            update_plots(axs, reliability_scores, recovery_times, latencies, throughputs)
        
        print(f'\rSimulation progress: {((cur+1)/max(reliability_iterations, performance_iterations) * 100):.2f}%')

    sys.stdout.flush()
    plt.ioff()
    plt.show()

if __name__ == "__main__":
    measure_and_plot()
