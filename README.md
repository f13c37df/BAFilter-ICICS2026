# BAFilter: Benign Activity Filter

This repository provides the official implementation of the Benign Activity Filter (BAFilter), a pre-processor designed for Efficient Provenance-based Log Analysis[cite: 1]. It was accepted at the 28th International Conference on Information and Communications Security (ICICS 2026)[cite: 1].

BAFilter aims to mitigate the "dependency explosion" problem in Data Provenance[cite: 1]. It utilizes natural language processing (FastText) to vectorize activity content and removes frequently occurring benign activities based on cosine similarity, effectively shrinking the search space placed before a detector[cite: 1].

## Prerequisites
- **OS**: Ubuntu 22.04[cite: 1]
- **Python**: 3.10.12[cite: 1]
- **Dependencies**: `networkx`, `gensim`, `scikit-learn`, `numpy`, `openpyxl`, `matplotlib`, `nostril`

## Datasets & Preparation
The scripts evaluate the DARPA Transparent Computing (TC) Dataset: Engagement 3 (Theia) and Engagement 5 (Theia / Marple)[cite: 1].

### 1. Downloading Engagement 3
- Access the official Engagement 3 GitHub page: https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md[cite: 1]
- Click the Google Drive link on the page, navigate to the `data` folder, and select a target environment (e.g., `theia`)[cite: 1].
- Download all files ending with `.json.tar.gz`[cite: 1].

### 2. Downloading and Converting Engagement 5
Since Engagement 5 data is provided in binary (`.bin`) format, it must be converted to JSON and compressed into `.tar.gz` format before running the pipeline[cite: 1]:
- Access the DARPA TC GitHub page: https://github.com/darpa-i2o/Transparent-Computing[cite: 1]
- Follow the Google Drive link (https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf) to access the Engagement 5 directory[cite: 1].
- Download the raw data files from the `Data` folder (e.g., `theia` or `marple`)[cite: 1].
- Download `ta3-java-consumer.tar.gz` from the `Tools` folder in the Engagement 5 directory[cite: 1].
- Place and run `tools/bin2json.py` inside the extracted `ta3-java-consumer` directory structure (`ta3-java-consumer/tc-bbn-kafka/`) to convert `.bin` files into JSON[cite: 1]:
  ```bash
  python bin2json.py
  ```
- Compress the generated JSON files back into `.tar.gz` format (matching the original naming convention like `ta1-theia-e5-official-1.json.tar.gz`)[cite: 1]:
  ```bash
  tar -zcvf xxxx.tar.gz directory
  ```

## Repository Structure

```text
BAFilter-ICICS2026/
├── phase1_extraction/          # Data preprocessing scripts (Dataset/OS-dependent)[cite: 1]
├── phase2_feature_extraction/  # Vectorization and node-set construction[cite: 1]
├── phase3_labeling/            # Similarity-based labeling[cite: 1]
├── phase4_reduction/           # Graph reduction scripts (Memory-optimized)[cite: 1]
├── tools/                      # Dataset analysis and conversion utilities[cite: 1]
├── ground_truth/               # Malicious node UUID lists (IoCs)[cite: 1]
└── README.md
```

## Implementation Notes & Instructions

### Phase 1: Data Preprocessing (`phase1_extraction/`)
- **THREATRACE Integration**: Preprocessing depends on the THREATRACE framework (https://github.com/threaTrace-detector/threaTrace)[cite: 1]. Place `phase1.py` inside the `threaTrace-master/scripts/` directory[cite: 1].
- **Memory Management**: For the massive Engagement 5 datasets (approx. 1.0 TB uncompressed), the E5 scripts use a disk-based SQLite approach to bypass memory constraints[cite: 1].
- **OS Architecture Adaptation**: Windows (Marple) environments exhibit different log characteristics and entropy[cite: 1]. The `phase1_E5_Marple.py` script specifically retrieves file paths from `predicateObjectPath` during edge generation to properly map relationships[cite: 1].
- **Schema Version**: When using Engagement 5 datasets, ensure that references to schema versions like `cdm18` are changed to `cdm20`[cite: 1].

### Phase 2: Feature Extraction & Node-set Construction (`phase2_feature_extraction/`)
- **NODLINK Integration**: This phase depends on the NODLINK framework (https://github.com/PKU-ASAL/Simulated-Data)[cite: 1]. Place the phase2 scripts inside the simulated-data root directory and ensure intermediate files are stored in a `data` folder[cite: 1].
- **Activity Granularity**: The node-set size is set to `5`, explicitly optimized to balance context retention and semantic dilution[cite: 1].
- **Feature Vector**: The node-set feature vector is calculated as a weighted sum of command lines, file objects, and network flows[cite: 1].

### Phase 3: Similarity-based Labeling (`phase3_labeling/`)
- **Ground Truth**: This phase requires a malicious node list (`mal_uuid.txt`)[cite: 1]. Pre-extracted lists for each dataset are provided in the `ground_truth/` directory (e.g., `mal_uuid_E3.txt`)[cite: 1]. Copy or rename the appropriate file to `mal_uuid.txt` and place it in your working data directory before running[cite: 1]. You can also use `tools/search.py` to search for Indicator of Compromise (IoC) strings from the DARPA Ground Truth reports[cite: 1].

### Phase 4: Similarity-based Graph Reduction (`phase4_reduction/`)
- Filters out frequent benign activities from the provenance graph[cite: 1].
- **Dynamic Similarity Thresholds**: The optimal threshold heavily depends on the OS[cite: 1]. We recommend `0.95` for Linux (Theia) to achieve high reduction with minimal false negatives[cite: 1]. For Windows (Marple), relax the threshold to `0.85` to absorb dynamic OS noise[cite: 1].
- Choose `phase4_memory.py` for smaller datasets or `phase4_disk.py` to utilize SQLite for large datasets[cite: 1].

### Utilities (`tools/`)
- Contains supplementary scripts for analyzing dataset distributions[cite: 1].
- **`cmdline_count.py` & `syscall_count.py`**: Count and output occurrence frequencies of command lines and event types[cite: 1]. *Note: Change the target schema to `cdm18` for Engagement 3, and `cdm20` for Engagement 5 within the scripts*[cite: 1].

## Citation
If you use this code or our method in your research, please cite our ICICS 2026 paper[cite: 1]:

```bibtex
@inproceedings{niwase2026benign,
  title={Benign Activity Filter: A Benign Activity Extraction Method for Efficient Provenance-based Log Analysis},
  author={Ryo Niwase and Taishin Saito and Kuniyasu Suzaki and Masaki Hashimoto},
  booktitle={The 28th International Conference on Information and Communications Security (ICICS 2026)},
  year={2026}
}
```
