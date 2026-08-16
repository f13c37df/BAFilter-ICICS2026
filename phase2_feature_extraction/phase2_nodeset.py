import networkx as nx
import re
import json
import numpy as np
import time
import os

NODESET = 5

# Base directory
BASE_DIR = 'data'

# Input file path
input_file = os.path.join(BASE_DIR, 'valid_edges_details_train.txt')

# Output file paths
output_gml_file = os.path.join(BASE_DIR, 'graph.gml')
output_results_file = os.path.join(BASE_DIR, 'calculation_results.json')

# Load vector information
cmdline_vectors = json.load(open(os.path.join(BASE_DIR, 'cmdline_vectors.json')))
filename_vectors = json.load(open(os.path.join(BASE_DIR, 'filename_vectors.json')))
netflow_vectors = json.load(open(os.path.join(BASE_DIR, 'netflow_vectors.json')))

# Start execution time measurement
start_time = time.time()

# Initialize graph
G = nx.DiGraph()

# Count events
P = 0
Pfi = 0
Pni = 0

# Read and parse file
with open(input_file, 'r') as f:
    lines = f.readlines()
    P = len(lines)
    for line in lines:
        if 'FILE_OBJECT' in line:
            Pfi += 1
        if 'NetFlowObject' in line:
            Pni += 1

# Calculate weights
Wfi = np.log(P / Pfi) if Pfi > 0 else 0
Wni = np.log(P / Pni) if Pni > 0 else 0
Wc = (Wfi + Wni) / 2

# Build graph
with open(input_file, 'r') as f:
    for line in f:
        match = re.match(r'Event UUID:\s*(\S+), EventType:\s*(\S+), srcId:\s*(\S+), srcType:\s*(\S+), dstId1:\s*(\S+), dstType1:\s*(\S+)', line)
        if match:
            event_uuid, event_type, src_id, src_type, dst_id, dst_type = match.groups()
            G.add_edge(src_id, dst_id, event_uuid=event_uuid, event_type=event_type)

# Count connected components with 5 or more connected nodes
subgraphs = []
subgraph_count = 0
for component in nx.connected_components(G.to_undirected()):
    subgraph = G.subgraph(component).copy()
    if subgraph.number_of_nodes() >= NODESET:
        subgraphs.append(subgraph)
        subgraph_count += 1

# Calculations using vector information
results = []

# Define embedding_size
embedding_size = 256

for subgraph in subgraphs:
    nodes = list(subgraph.nodes())
    num_nodes = len(nodes)
    for i in range(num_nodes - NODESET + 1):  # Slide by 5 nodes
        subset_nodes = nodes[i:i + NODESET]
        edges = list(subgraph.edges(subset_nodes))[:NODESET]

        Vc = np.zeros(embedding_size)
        Vfi_sum = np.zeros(embedding_size)
        Vni_sum = np.zeros(embedding_size)

        for node in subset_nodes:
            if node in cmdline_vectors:
                Vc += np.mean(cmdline_vectors[node]['vectors'], axis=0)
            if node in filename_vectors:
                Vfi_sum += np.mean(filename_vectors[node]['vectors'], axis=0)
            if node in netflow_vectors:
                Vni_sum += np.mean(netflow_vectors[node]['vectors'], axis=0)

        Vp = Wc * Vc + Wfi * Vfi_sum + Wni * Vni_sum
        results.append({'nodes': subset_nodes, 'Vp': Vp.tolist()})

# Generate GML file
nx.write_gml(G, output_gml_file)

# Output calculation results to file
with open(output_results_file, 'w') as f:
    json.dump(results, f, indent=4)

# Output results
for result in results:
    print(f"Nodes: {result['nodes']}")
    print(f"Vp: {result['Vp']}")

# Output the number of subgraphs and calculated node sets
print(f"Number of subgraphs with {NODESET} or more nodes: {subgraph_count}")
print(f"Number of node sets calculated: {len(results)}")

print("Calculation completed.")
print(f"GML file saved as {output_gml_file}")
print(f"Calculation results saved as {output_results_file}")

# End execution time measurement
end_time = time.time()
execution_time = end_time - start_time

print(f"Execution time: {execution_time} seconds")