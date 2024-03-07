#!/usr/bin/python3

import json
import matplotlib.pyplot as plt
import os

def load_data(file_path):
    """Load data from a JSON file."""
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return json.load(file)
    else:
        raise FileNotFoundError(f"No such file or directory: '{file_path}'")

def plot_comparison(metrics_legacy, metrics_group):
    """Plot boxplots for two sets of metrics in the same window."""
    fig, axs = plt.subplots(2, 2, figsize=(12, 8))  # Create 2x2 subplots
    metrics_names = ['reliability_scores', 'recovery_times', 'latencies', 'throughputs']
    axs = axs.flatten()  # Flatten the array to make it easier to iterate over
    
    for i, metric_name in enumerate(metrics_names):
        axs[i].boxplot([metrics_legacy[metric_name], metrics_group[metric_name]], labels=['Legacy Test', 'Group Test'])
        axs[i].set_title(f'Comparison of {metric_name}')

    plt.tight_layout()  # Adjust subplots to fit in the window
    plt.show()

if __name__ == "__main__":
    metrics_legacy = {}
    metrics_group = {}

    # Lloading data into dictionaries (repeated for all metrics)
    metrics_legacy['reliability_scores'] = load_data('legacytest_1/reliability_scores.json')
    metrics_group['reliability_scores'] = load_data('grouptest_1/reliability_scores.json')

    metrics_legacy['recovery_times'] = load_data('legacytest_1/recovery_times.json')
    metrics_group['recovery_times'] = load_data('grouptest_1/recovery_times.json')
    
    metrics_legacy['latencies'] = load_data('legacytest_1/latencies.json')
    metrics_group['latencies'] = load_data('grouptest_1/latencies.json')
    
    metrics_legacy['throughputs'] = load_data('legacytest_1/throughputs.json')
    metrics_group['throughputs'] = load_data('grouptest_1/throughputs.json')
    
    # Plotting all metrics comparison on the same window
    plot_comparison(metrics_legacy, metrics_group)
