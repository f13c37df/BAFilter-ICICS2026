import networkx as nx
import json
import time
import os
import re
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
from gensim.models import FastText

# ==========================================
# Configuration Parameters
# ==========================================
BASE_DIR = 'data'            # Data folder
OUTPUT_DIR = 'output'        # Output folder
TOP_N = 5                 # Use top N benign labels
SIMILARITY_THRESHOLD = 0.5 # Similarity threshold for deletion
EMBEDDING_SIZE = 256         # Vector embedding size
NODE_SET_SIZE = 5          # Node set size (based on the paper)

# Pre-trained model filenames (created in phase 2)
MODEL_NAMES = {
    'cmdline': 'cmdline-embedding.model',
    'filename': 'filepath-embedding.model',
    'netflow': 'netflow-embedding.model'
}
# ==========================================

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def get_filepath(filename, output=False):
    return os.path.join(OUTPUT_DIR if output else BASE_DIR, filename)

def vectorize(vector_list):
    """Convert a list to a numpy array"""
    vec = np.array(vector_list, dtype=np.float32)
    return np.nan_to_num(vec)

def sanitize_string(text):
    """
    Equivalent to sanitize_string in phase 2.
    Replace slashes with spaces and tokenize based on the documentation.
    """
    if not text:
        return []
    # Replace slashes with spaces based on the documentation
    text = text.replace('/', ' ').replace('\\', ' ')
    # Convert to lowercase and split by whitespace
    tokens = text.lower().split()
    return tokens

# ---------------------------------------------------------
# 1. Vector generation process compliant with Phase 2
# ---------------------------------------------------------

def load_model(model_key):
    filename = MODEL_NAMES[model_key]
    path = get_filepath(filename)
    if not os.path.exists(path):
        print(f"  Error: Model {filename} not found.")
        return None
    print(f"  Loading model: {filename}")
    return FastText.load(path)

def generate_cmdline_vectors():
    """Reproduce the logic of phase2_cmdline.py"""
    print("Generating cmdline vectors...")
    input_file = get_filepath('subject_info.txt')
    if not os.path.exists(input_file):
        print(f"  Warning: {input_file} not found.")
        return {}

    model = load_model('cmdline')
    if not model: return {}

    uuid_vectors = {}
    count = 0
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Format close to the regular expression in the documentation (comma-handled)
            # "uuid, cmdLine: ..., parentSubject:"
            match = re.search(r'^(\S+),\s*cmdLine:\s*(.*?),', line)
            if match:
                uuid = match.group(1).strip()
                cmdline = match.group(2)
                
                if cmdline and cmdline.strip().lower() != 'n/a':
                    # Documentation: replace('/', ' ') -> sanitize
                    cmdline = cmdline.replace('/', ' ')
                    tokens = sanitize_string(cmdline)
                    
                    # Vectorization
                    vectors = [model.wv[word] for word in tokens if word in model.wv]
                    if vectors:
                        # If multiple words, take the average (perform the process from phase2_nodeset.py here)
                        uuid_vectors[uuid] = np.mean(vectors, axis=0).astype(np.float32)
                        count += 1
    
    print(f"  Generated {count} cmdline vectors.")
    return uuid_vectors

def generate_filename_vectors():
    """Reproduce the logic of phase2_filename.py"""
    print("Generating filename vectors...")
    input_file = get_filepath('fileobject_info.txt')
    if not os.path.exists(input_file):
        print(f"  Warning: {input_file} not found.")
        return {}

    model = load_model('filename')
    if not model: return {}

    uuid_vectors = {}
    count = 0

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Documentation: r'(\S+), filename:\s*(.*)'
            match = re.search(r'^(\S+),\s*filename:\s*(.*)', line)
            if match:
                uuid = match.group(1).strip()
                filename = match.group(2)
                
                if filename and filename.strip().lower() != 'n/a':
                    # Documentation: replace('/', ' ')
                    filename = filename.replace('/', ' ')
                    tokens = sanitize_string(filename)
                    
                    vectors = [model.wv[word] for word in tokens if word in model.wv]
                    if vectors:
                        uuid_vectors[uuid] = np.mean(vectors, axis=0).astype(np.float32)
                        count += 1
    
    print(f"  Generated {count} filename vectors.")
    return uuid_vectors

def generate_netflow_vectors():
    """Reproduce the logic of phase2_netflow.py"""
    print("Generating netflow vectors...")
    input_file = get_filepath('netflowobject_info.txt')
    if not os.path.exists(input_file):
        print(f"  Warning: {input_file} not found.")
        return {}

    model = load_model('netflow')
    if not model: return {}

    uuid_vectors = {}
    count = 0

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Documentation: r'(\S+), remoteAddress:\s*(.*?),.*?remotePort:\s*(\d+)'
            match = re.search(r'^(\S+),\s*remoteAddress:\s*(.*?),.*?remotePort:\s*(\d+)', line)
            if match:
                uuid = match.group(1).strip()
                addr = match.group(2).strip()
                port = match.group(3).strip()
                
                if addr.lower() != 'na':
                    # Documentation: IP splitting logic
                    if addr.lower() == 'netlink':
                        tokens = ['netlink']
                    else:
                        # Split IP by dots and add port
                        tokens = addr.split('.') + [port]
                    
                    # Input into the model as strings
                    vectors = [model.wv[str(t)] for t in tokens if str(t) in model.wv]
                    if vectors:
                        uuid_vectors[uuid] = np.mean(vectors, axis=0).astype(np.float32)
                        count += 1
                        
    print(f"  Generated {count} netflow vectors.")
    return uuid_vectors

# ---------------------------------------------------------
# 2. Graph construction and weight calculation compliant with Phase 2
# ---------------------------------------------------------

def build_graph_and_calc_weights():
    """Reproduce the logic of phase2_nodeset.py"""
    edge_file = get_filepath('valid_edges_details.txt')
    print(f"Reading edges from {edge_file}...")
    
    G = nx.DiGraph()
    P, Pfi, Pni = 0, 0, 0
    
    if not os.path.exists(edge_file):
        print(f"Error: {edge_file} not found.")
        return None, 0, 0, 0

    with open(edge_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            P += 1
            # Documentation: Count statistical information
            if 'FILE_OBJECT' in line: Pfi += 1
            if 'NetFlowObject' in line: Pni += 1
            
            # Documentation: Extract edge information
            # Fix regex to handle commas: srcId: uuid, srcType...
            match = re.search(r'srcId:\s*([^,]+),.*dstId1:\s*([^,]+),', line)
            if match:
                src = match.group(1).strip()
                dst = match.group(2).strip()
                G.add_edge(src, dst)

    # Documentation: Weight calculation
    Wfi = np.log(P / Pfi) if Pfi > 0 else 0
    Wni = np.log(P / Pni) if Pni > 0 else 0
    Wc = (Wfi + Wni) / 2
    
    print(f"  Weights: Wc={Wc:.4f}, Wfi={Wfi:.4f}, Wni={Wni:.4f}")
    print(f"  Graph constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G, Wc, Wfi, Wni

# ---------------------------------------------------------
# 3. Retrieve benign vectors for comparison
# ---------------------------------------------------------
def get_all_benign_vectors(top_n):
    """Retrieve all vectors from trained data (labeled_node_sets.json)"""
    path = get_filepath('labeled_node_sets.json')
    print(f"Loading benign patterns from {path}...")
    if not os.path.exists(path):
        print("  Error: Labeled data not found.")
        return None

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        labeled_data = json.load(f)

    # Group by label
    label_groups = defaultdict(list)
    for item in labeled_data:
        if 'benign' in item['label']:
            label_groups[item['label']].append(vectorize(item['Vp']))

    # Get top N by frequency
    sorted_labels = sorted(label_groups.items(), key=lambda x: len(x[1]), reverse=True)
    target_labels = sorted_labels[:top_n]

    all_vectors = []
    for label, vectors in target_labels:
        all_vectors.extend(vectors)
    
    if not all_vectors:
        print("  Error: No benign vectors found.")
        return None

    matrix = np.array(all_vectors, dtype=np.float32)
    print(f"  Prepared {len(matrix)} benign vectors for comparison.")
    return matrix

# ---------------------------------------------------------
# Main process: Phase 2 + 4 integrated flow
# ---------------------------------------------------------
def main():
    start_time = time.time()
    
    # --- Step 1: Vector generation (on-memory) ---
    cmdline_vectors = generate_cmdline_vectors()
    filename_vectors = generate_filename_vectors()
    netflow_vectors = generate_netflow_vectors()

    if not (cmdline_vectors or filename_vectors or netflow_vectors):
        print("Error: No vectors generated. Check input files and models.")
        return

    # --- Step 2: Prepare benign vector matrix ---
    benign_matrix = get_all_benign_vectors(TOP_N)
    if benign_matrix is None: return

    # --- Step 3: Graph construction and weight calculation ---
    G, Wc, Wfi, Wni = build_graph_and_calc_weights()
    if G is None: return
    initial_nodes = G.number_of_nodes()

    # --- Step 4: Filtering (Phase 2 feature calculation + Phase 4 determination) ---
    print("\n=== Filtering Node Sets ===")
    nodes_to_remove = set()
    processed_count = 0
    
    # Process per connected component
    # Keep this as a generator if out of memory
    subgraphs = [G.subgraph(c).copy() for c in nx.connected_components(G.to_undirected())]
    
    for subgraph in subgraphs:
        nodes = list(subgraph.nodes())
        if len(nodes) < NODE_SET_SIZE: continue

        # Sliding window processing
        for i in range(len(nodes) - NODE_SET_SIZE + 1):
            subset = nodes[i : i + NODE_SET_SIZE]
            
            # Calculate feature vector (reproduction of phase2_nodeset.py)
            Vc = np.zeros(EMBEDDING_SIZE, dtype=np.float32)
            Vfi = np.zeros(EMBEDDING_SIZE, dtype=np.float32)
            Vni = np.zeros(EMBEDDING_SIZE, dtype=np.float32)
            
            for node in subset:
                # Node vectors are already averaged, so just summing them is sufficient here
                if node in cmdline_vectors: Vc += cmdline_vectors[node]
                if node in filename_vectors: Vfi += filename_vectors[node]
                if node in netflow_vectors: Vni += netflow_vectors[node]
            
            # Weighted synthesis
            Vp = Wc * Vc + Wfi * Vfi + Wni * Vni
            
            # Similarity determination (Phase 4)
            sims = cosine_similarity(Vp.reshape(1, -1), benign_matrix)[0]
            if np.max(sims) >= SIMILARITY_THRESHOLD:
                nodes_to_remove.update(subset)
            
            processed_count += 1
            if processed_count % 5000 == 0:
                print(f"  Processed {processed_count} sets...")

    # --- Step 5: Execute deletion and save results ---
    print(f"\nRemoving {len(nodes_to_remove)} nodes...")

    initial_nodes = G.number_of_nodes()
    initial_edges = G.number_of_edges()

    G.remove_nodes_from(nodes_to_remove)
    
    final_nodes = G.number_of_nodes()
    final_edges = G.number_of_edges()
    reduction_rate = (1 - final_nodes / initial_nodes) * 100 if initial_nodes > 0 else 0
    print("-" * 30)
    print(f"Initial Nodes: {initial_nodes} -> Final Nodes: {final_nodes}")
    print(f"Initial Edges: {initial_edges} -> Final Edges: {final_edges}")
   
    print(f"Reduction Rate: {reduction_rate:.2f}%")
    
    # Save
    output_gml = get_filepath('reduced_network_graph.gml', output=True)
    nx.write_gml(G, output_gml)
    print(f"Saved to {output_gml}")
    
    # Check False Negatives (FN)
    mal_path = get_filepath('mal_uuid.txt')
    if os.path.exists(mal_path):
        with open(mal_path, 'r', encoding='utf-8', errors='ignore') as f:
            malicious_uuids = set(line.strip() for line in f)
        fns = [uuid for uuid in malicious_uuids if uuid in nodes_to_remove]

        remaining_nodes = set(G.nodes())
        remaining_malicious = [uuid for uuid in remaining_nodes if uuid  in malicious_uuids]
        fps = len(remaining_nodes) - len(remaining_malicious)
        tps = len(remaining_malicious)

        print(f"False Negatives: {len(fns)}")
        print(f"False Positives: {fps}")
        print(f"True Negatives: {tps}")

    print(f"Total Execution time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()