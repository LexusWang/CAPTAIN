import resource
import numpy as np
import sys

def print_memory_usage(description):
    # Get the maximum resident set size (in kilobytes on Linux, bytes on macOS)
    max_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    
    # On macOS, ru_maxrss is in bytes, so we convert it to kilobytes for consistency
    if sys.platform == 'darwin':
        max_rss /= 1024
    
    print(f"{description}: {max_rss} KB")

print_memory_usage("Memory usage before allocation")

# Example of a memory-intensive operation: Allocating a large NumPy array
large_array = np.zeros((10000, 10000))

print_memory_usage("Memory usage after allocation")
