from gensim.models import FastText
from argparse import ArgumentParser
import re
import json
import pandas as pd
from nostril.nonsense_detector import nonsense
import string
from tools import sanitize_string
import time

# Start execution time measurement
start_time = time.time()

# Set command line arguments
parser = ArgumentParser()
parser.add_argument("--epoch", type=int, default=100)
parser.add_argument("--e", type=int, default=256)
parser.add_argument("--d", type=str, default='data')
args = parser.parse_args()

epoch = args.epoch
dataset = args.d
embedding_size = args.e
input_file = dataset + '/subject_info_train.txt'

# Extract cmdline and uuid from text file
corpus = []
cmdline_to_uuid = {}

with open(input_file, 'r') as f:
    while True:
        line = f.readline()
        if not line:
            break
        if line == '\n' or line == 'None' or line == 'none':
            continue
        if 'cmdLine:' in line:
            match = re.search(r'(\S+), cmdLine:\s*(.*?),\s*parentSubject:', line)
            if match:
                uuid = match.group(1)
                cmdline = match.group(2)
                if cmdline.strip().lower() != 'n/a':
                    cmdline = cmdline.replace('/', ' ')
                    splitline = sanitize_string(cmdline.strip())
                    corpus.append(splitline)
                    cmdline_to_uuid[uuid] = cmdline

# Train FastText model
model = FastText(min_count=2, vector_size=embedding_size, workers=30, alpha=0.01, window=3, negative=5)
model.build_vocab(corpus)
model.train(corpus, epochs=epoch, total_examples=model.corpus_count)
model.save(dataset + '/cmdline-embedding.model')

# Convert each cmdline to vector and save
uuid_to_vectors = {}

for uuid, cmdline in cmdline_to_uuid.items():
    splitline = sanitize_string(cmdline.strip())
    sentence_vector = [model.wv[word].tolist() for word in splitline if word in model.wv]
    uuid_to_vectors[uuid] = {
        'cmdline': cmdline,
        'vectors': sentence_vector
    }

# Save vectors, original cmdline, and UUID to file
output_file = dataset + '/cmdline_vectors.json'
with open(output_file, 'w') as f:
    json.dump(uuid_to_vectors, f, indent=4)

print(f"Data saved to {output_file}")

# End execution time measurement
end_time = time.time()
execution_time = end_time - start_time
print(f"Execution time: {execution_time} seconds")