import json
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from multiprocessing import Manager, Pool, cpu_count
import time
import os

# Base directory
BASE_DIR = 'data'

# Start execution time measurement
start_time = time.time()

# Threshold setting
similarity_threshold = 1.0

def get_filepath(filename):
    """Get the path of the specified filename within `BASE_DIR`"""
    return os.path.join(BASE_DIR, filename)

def load_json(filename):
    with open(get_filepath(filename), 'r') as file:
        return json.load(file)

def load_malicious_uuids(filename):
    with open(get_filepath(filename), 'r') as file:
        return set(line.strip() for line in file)

def vectorize(vector):
    return np.array(vector)

def calculate_cosine_similarity(vector1, vector2):
    return cosine_similarity([vector1], [vector2])[0][0]

def contains_nan(vector):
    return np.isnan(vector).any()

def label_node_set(node_set, malicious_uuids, label_counts):
    nodes = node_set['nodes']
    for node in nodes:
        if node in malicious_uuids:
            label = f"malicious{label_counts['malicious'] + 1}"
            label_counts['malicious'] += 1
            return label
    label = f"benign{label_counts['benign'] + 1}"
    label_counts['benign'] += 1
    return label

def process_chunk(chunk, malicious_uuids, global_labeled_vectors, similarity_threshold, global_label_counts):
    local_label_counts = {"malicious": 0, "benign": 0}
    labeled_sets = []

    for node_set in chunk:
        nodes = node_set['nodes']
        current_vector = vectorize(node_set['Vp'])

        if contains_nan(current_vector):
            continue

        assigned_label = None
        for label, vectors in global_labeled_vectors.items():
            for vec in vectors:
                labeled_vector = vectorize(vec['Vp'])
                if contains_nan(labeled_vector):
                    continue
                similarity = calculate_cosine_similarity(current_vector, labeled_vector)
                if similarity >= similarity_threshold:
                    assigned_label = label
                    break
            if assigned_label:
                break

        if not assigned_label:
            assigned_label = label_node_set(node_set, malicious_uuids, global_label_counts)
            if assigned_label not in global_labeled_vectors:
                global_labeled_vectors[assigned_label] = []
            global_labeled_vectors[assigned_label].append(node_set)

        labeled_sets.append({'nodes': nodes, 'label': assigned_label, 'Vp': node_set['Vp']})

    return labeled_sets, local_label_counts

if __name__ == "__main__":
    # Load node UUID list
    malicious_uuids = load_malicious_uuids('mal_uuid.txt')

    # Load calculation results
    calculation_results = load_json('calculation_results.json')

    # Split node sets into chunks of 500
    chunk_size = 500
    chunks = [calculation_results[i:i + chunk_size] for i in range(0, len(calculation_results), chunk_size)]

    manager = Manager()
    global_labeled_vectors = manager.dict()
    global_label_counts = manager.dict({"malicious": 0, "benign": 0})

    all_labeled_sets = []

    # Create process pool
    with Pool(cpu_count()) as pool:
        results = pool.starmap(process_chunk, [(chunk, malicious_uuids, global_labeled_vectors, similarity_threshold, global_label_counts) for chunk in chunks])

    # Integrate results
    for labeled_sets, local_label_counts in results:
        all_labeled_sets.extend(labeled_sets)

    # Save overall labeling results
    labeled_output_file = get_filepath('labeled_node_sets.json')
    with open(labeled_output_file, 'w') as f:
        json.dump(all_labeled_sets, f, indent=4)

    print(f"Labeled node sets saved to {labeled_output_file}")

    # End execution time measurement
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution time: {execution_time} seconds")