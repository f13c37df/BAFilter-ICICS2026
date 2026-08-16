from gensim.models import FastText
from argparse import ArgumentParser
from tools import sanitize_string
import re
import json
import numpy as np
import time

# Start execution time measurement
start_time = time.time()


# Function to convert IP address to a vector
def ip_to_vector(ip):
    parts = ip.split('.')
    return [int(part) for part in parts]

# Set command line arguments
parser = ArgumentParser()
parser.add_argument("--epoch", type=int, default=100)
parser.add_argument("--e", type=int, default=256)
parser.add_argument("--d", type=str, default='data')
args = parser.parse_args()

epoch = args.epoch
dataset = args.d
embedding_size = args.e
input_file = dataset + '/netflowobject_info_train.txt'

# Extract remoteAddress and uuid from the text file
corpus = []
netflow_to_uuid = {}

with open(input_file, 'r') as f:
    for line in f:
        match = re.search(r'(\S+), remoteAddress:\s*(.*?),\s*remotePort:\s*(\d+)', line)
        if match:
            uuid = match.group(1)
            remote_address = match.group(2)
            remote_port = match.group(3)
            if remote_address.strip().lower() != 'na':
                if remote_address.strip().lower() == 'netlink':
                    netflow_info = [remote_address]
                else:
                    netflow_info = ip_to_vector(remote_address) + [int(remote_port)]
                splitline = [str(item) for item in netflow_info]
                corpus.append(splitline)
                netflow_to_uuid[uuid] = netflow_info

# Train FastText model
model = FastText(min_count=2, vector_size=embedding_size, workers=4, alpha=0.01, window=3, negative=5)
model.build_vocab(corpus)
model.train(corpus, epochs=epoch, total_examples=model.corpus_count)
model.save(dataset + '/netflow-embedding.model')

# Convert each netflow to a vector and save
uuid_to_vectors = {}

for uuid, netflow_info in netflow_to_uuid.items():
    splitline = [str(item) for item in netflow_info]
    sentence_vector = [model.wv[word].tolist() for word in splitline if word in model.wv]
    uuid_to_vectors[uuid] = {
        'netflow_info': netflow_info,
        'vectors': sentence_vector
    }

# Save vectors, original netflow_info, and UUID to a file
output_file = dataset + '/netflow_vectors.json'
with open(output_file, 'w') as f:
    json.dump(uuid_to_vectors, f, indent=4)

print(f"Data saved to {output_file}")

# End execution time measurement
end_time = time.time()
execution_time = end_time - start_time
print(f"Execution time: {execution_time} seconds")