import networkx as nx
import json
import time
import os
import re
import numpy as np
import sqlite3
import gc
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
from gensim.models import FastText

# ==========================================
# Configuration Parameters
# ==========================================
BASE_DIR = 'data'            # Data folder
OUTPUT_DIR = 'output'        # Output folder
VECTOR_DB_PATH = os.path.join(OUTPUT_DIR, 'vectors.db') # DB for saving vectors

TOP_N = 5                    # Use top N benign labels
SIMILARITY_THRESHOLD = 0.85  # Similarity threshold for deletion
EMBEDDING_SIZE = 256         # Vector embedding size
NODE_SET_SIZE = 5            # Node set size (based on the paper)

# Pre-trained model filenames
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
    """Equivalent to sanitize_string in phase 2"""
    if not text: return []
    text = text.replace('/', ' ').replace('\\', ' ')
    tokens = text.lower().split()
    return tokens

# ---------------------------------------------------------
# 0. DB management functions (key to memory saving)
# ---------------------------------------------------------
def init_vector_db():
    if os.path.exists(VECTOR_DB_PATH):
        os.remove(VECTOR_DB_PATH)
    
    conn = sqlite3.connect(VECTOR_DB_PATH)
    c = conn.cursor()
    # Save UUID, type (v_type), and vector data
    # This allows reproducing the same logic as "if node in cmdline_vectors"
    c.execute('''
        CREATE TABLE vectors (
            uuid TEXT,
            v_type TEXT,
            vector BLOB,
            PRIMARY KEY (uuid, v_type)
        )
    ''')
    # Create index (for faster search)
    c.execute('CREATE INDEX idx_uuid ON vectors (uuid)')
    
    c.execute('PRAGMA synchronous = OFF')
    c.execute('PRAGMA journal_mode = MEMORY')
    conn.commit()
    return conn

def save_vectors_batch(conn, batch):
    if not batch: return
    conn.executemany('INSERT OR REPLACE INTO vectors (uuid, v_type, vector) VALUES (?, ?, ?)', batch)
    conn.commit()

# ---------------------------------------------------------
# 1. Vector generation process compliant with Phase 2 (DB saving version)
# ---------------------------------------------------------

def load_model(model_key):
    filename = MODEL_NAMES[model_key]
    path = get_filepath(filename)
    if not os.path.exists(path):
        print(f"  Error: Model {filename} not found.")
        return None
    print(f"  Loading model: {filename}")
    return FastText.load(path)

def generate_vectors_to_db(conn, model_key, input_filename, regex_pattern, logic_func):
    """Generic vector generation function: saves to DB instead of a dictionary"""
    print(f"Generating {model_key} vectors...")
    input_file = get_filepath(input_filename)
    if not os.path.exists(input_file):
        print(f"  Warning: {input_file} not found.")
        return

    model = load_model(model_key)
    if not model: return

    count = 0
    batch = []
    BATCH_SIZE = 100000

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = re.search(regex_pattern, line)
            if match:
                uuid, tokens = logic_func(match)
                
                # Vectorization
                vectors = [model.wv[word] for word in tokens if word in model.wv]
                if vectors:
                    # Averaging (as in the original logic)
                    mean_vec = np.mean(vectors, axis=0).astype(np.float32)
                    # To DB (UUID, type, binary)
                    batch.append((uuid, model_key, mean_vec.tobytes()))
                    count += 1
            
            if len(batch) >= BATCH_SIZE:
                save_vectors_batch(conn, batch)
                batch = []
                print(f"  Processed {count} records...", end='\r')

    save_vectors_batch(conn, batch)
    print(f"\n  Generated {count} {model_key} vectors.")
    
    # Free memory
    del model
    gc.collect()

# --- Each extraction logic (exactly the same as original) ---
def logic_cmdline(match):
    uuid = match.group(1).strip()
    cmdline = match.group(2)
    if cmdline and cmdline.strip().lower() != 'n/a':
        cmdline = cmdline.replace('/', ' ')
        return uuid, sanitize_string(cmdline)
    return uuid, []

def logic_filename(match):
    uuid = match.group(1).strip()
    filename = match.group(2)
    if filename:
        filename = filename.replace('/', ' ')
        return uuid, sanitize_string(filename)
    return uuid, []

def logic_netflow(match):
    uuid = match.group(1).strip()
    addr = match.group(2).strip()
    port = match.group(3).strip()
    if addr.lower() != 'na':
        if addr.lower() == 'netlink':
            tokens = ['netlink']
        else:
            tokens = addr.split('.') + [port]
        return uuid, tokens
    return uuid, []

# ---------------------------------------------------------
# 2. Graph construction and weight calculation compliant with Phase 2 (Unchanged)
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
            if 'FILE_OBJECT' in line: Pfi += 1
            if 'NetFlowObject' in line: Pni += 1
            
            match = re.search(r'srcId:\s*([^,]+),.*dstId1:\s*([^,]+),', line)
            # Not in the original code, but considering dstId2 just in case for q.py compatibility
            if not match:
                 match = re.search(r'srcId:\s*([^,]+),.*dstId2:\s*([^,]+),', line)

            if match:
                src = match.group(1).strip()
                dst = match.group(2).strip()
                G.add_edge(src, dst)

    Wfi = np.log(P / Pfi) if Pfi > 0 else 0
    Wni = np.log(P / Pni) if Pni > 0 else 0
    Wc = (Wfi + Wni) / 2
    
    print(f"  Weights: Wc={Wc:.4f}, Wfi={Wfi:.4f}, Wni={Wni:.4f}")
    print(f"  Graph constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G, Wc, Wfi, Wni

# ---------------------------------------------------------
# 3. Retrieve benign vectors for comparison (Unchanged)
# ---------------------------------------------------------
def get_all_benign_vectors(top_n):
    path = get_filepath('labeled_node_sets.json')
    print(f"Loading benign patterns from {path}...")
    if not os.path.exists(path):
        print("  Error: Labeled data not found.")
        return None

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        labeled_data = json.load(f)

    label_groups = defaultdict(list)
    for item in labeled_data:
        if 'benign' in item['label']:
            label_groups[item['label']].append(vectorize(item['Vp']))

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
# Main process: Phase 2 + 4 integrated flow (DB version)
# ---------------------------------------------------------
def main():
    start_time = time.time()
    
    # DB initialization
    print("Initializing Vector DB...")
    conn = init_vector_db()

    # --- Step 1: Vector generation (save to DB) ---
    # Cmdline
    generate_vectors_to_db(conn, 'cmdline', 'subject_info.txt', 
                           r'^(\S+),\s*cmdLine:\s*(.*?),', logic_cmdline)
    # Filename
    generate_vectors_to_db(conn, 'filename', 'fileobject_info.txt', 
                           r'^(\S+),\s*filename:\s*(.*)', logic_filename)
    # Netflow
    generate_vectors_to_db(conn, 'netflow', 'netflowobject_info.txt', 
                           r'^(\S+),\s*remoteAddress:\s*(.*?),.*?remotePort:\s*(\d+)', logic_netflow)

    # --- Step 2: Prepare benign vector matrix ---
    benign_matrix = get_all_benign_vectors(TOP_N)
    if benign_matrix is None: return

    # --- Step 3: Graph construction and weight calculation ---
    G, Wc, Wfi, Wni = build_graph_and_calc_weights()
    if G is None: return

    # --- Step 4: Filtering ---
    print("\n=== Filtering Node Sets (DB Mode) ===")
    nodes_to_remove = set()
    processed_count = 0
    
    # DB cursor (read-only)
    cursor = conn.cursor()
    
    # Fix: Use a generator instead of creating a copy list (memory optimization)
    for component in nx.connected_components(G.to_undirected()):
        if len(component) < NODE_SET_SIZE: continue
        nodes = list(component)

        # Sliding window processing
        for i in range(len(nodes) - NODE_SET_SIZE + 1):
            subset = nodes[i : i + NODE_SET_SIZE]
            
            # Vector sum for each type (reproduce original logic)
            Vc = np.zeros(EMBEDDING_SIZE, dtype=np.float32)
            Vfi = np.zeros(EMBEDDING_SIZE, dtype=np.float32)
            Vni = np.zeros(EMBEDDING_SIZE, dtype=np.float32)
            
            valid_vec_count = 0

            for node in subset:
                # Retrieve all (v_type, vector) from DB
                # Can retrieve all even if there are multiple types for a UUID
                cursor.execute("SELECT v_type, vector FROM vectors WHERE uuid=?", (node,))
                rows = cursor.fetchall()
                
                for row in rows:
                    v_type = row[0]
                    vec = np.frombuffer(row[1], dtype=np.float32)
                    
                    # Add by type (same logic as the original: if node in cmdline_vectors ...)
                    if v_type == 'cmdline':
                        Vc += vec
                    elif v_type == 'filename':
                        Vfi += vec
                    elif v_type == 'netflow':
                        Vni += vec
                    
                    valid_vec_count += 1
            
            if valid_vec_count == 0: continue

            # Weighted synthesis (same as the original formula)
            Vp = Wc * Vc + Wfi * Vfi + Wni * Vni
            
            # Similarity determination
            sims = cosine_similarity(Vp.reshape(1, -1), benign_matrix)[0]
            if np.max(sims) >= SIMILARITY_THRESHOLD:
                nodes_to_remove.update(subset)
            
            processed_count += 1
            if processed_count % 10000 == 0:
                print(f"  Processed {processed_count} windows...", end='\r')

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
        remaining_malicious = [uuid for uuid in remaining_nodes if uuid in malicious_uuids]
        fps = len(remaining_nodes) - len(remaining_malicious)
        tps = len(remaining_malicious)

        print(f"False Negatives: {len(fns)}")
        print(f"False Positives: {fps}")
        print(f"True Negatives: {tps}")

    # Delete DB
    conn.close()
    if os.path.exists(VECTOR_DB_PATH):
        os.remove(VECTOR_DB_PATH)

    print(f"Total Execution time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()