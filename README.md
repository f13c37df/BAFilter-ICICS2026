# BAFilter: Benign Activity Filter

This repository provides the official implementation of the Benign Activity Filter (BAFilter), a pre-processor designed for Efficient Provenance-based Log Analysis. It was accepted at the 28th International Conference on Information and Communications Security (ICICS 2026).

BAFilter aims to mitigate the "dependency explosion" problem in Data Provenance. It utilizes natural language processing (FastText) to vectorize activity content and removes frequently occurring benign activities based on cosine similarity, effectively shrinking the search space placed before a detector.

## Prerequisites
- **OS**: Ubuntu 22.04
- **Python**: 3.10.12
- **Dependencies**: `networkx`, `gensim`, `scikit-learn`, `numpy`, `openpyxl`, `matplotlib`, `nostril`

## Datasets & Preparation
The scripts evaluate the DARPA Transparent Computing (TC) Dataset: Engagement 3 (Theia) and Engagement 5 (Theia / Marple).

### 1. Downloading Engagement 3
- Access the official Engagement 3 GitHub page: `[https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md)`
- Click the Google Drive link on the page, navigate to the `data` folder, and select a target environment (e.g., `theia`).
- Download all files ending with `.json.tar.gz`.

### 2. Downloading and Converting Engagement 5
Since Engagement 5 data is provided in binary (`.bin`) format, it must be converted to JSON and compressed into `.tar.gz` format before running the pipeline:
- Access the DARPA TC GitHub page: `[https://github.com/darpa-i2o/Transparent-Computing](https://github.com/darpa-i2o/Transparent-Computing)`
- Follow the Google Drive link (`[https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)`) to access the Engagement 5 directory.
- Download the raw data files from the `Data` folder (e.g., `theia` or `marple`).
- Download `ta3-java-consumer.tar.gz` from the `Tools` folder in the Engagement 5 directory.
- Place and run `tools/bin2json.py` inside the extracted `ta3-java-consumer` directory structure (`ta3-java-consumer/tc-bbn-kafka/`) to convert `.bin` files into JSON:
  ```bash
  python bin2json.py
  ```
- Compress the generated JSON files back into `.tar.gz` format (matching the original naming convention like `ta1-theia-e5-official-1.json.tar.gz`):
  ```bash
  tar -zcvf xxxx.tar.gz directory
  ```

## Repository Structure

```text
BAFilter-ICICS2026/
├── phase1_extraction/          # Data preprocessing scripts (Dataset/OS-dependent)
├── phase2_feature_extraction/  # Vectorization and node-set construction
├── phase3_labeling/            # Similarity-based labeling
├── phase4_reduction/           # Graph reduction scripts (Memory-optimized)
├── tools/                      # Dataset analysis and conversion utilities
├── ground_truth/               # Malicious node UUID lists (IoCs)
└── README.md
```

## Implementation Notes & Instructions

### Phase 1: Data Preprocessing (`phase1_extraction/`)
- **THREATRACE Integration**: Preprocessing depends on the THREATRACE framework (`[https://github.com/threaTrace-detector/threaTrace](https://github.com/threaTrace-detector/threaTrace)`). Place `phase1.py` inside the `threaTrace-master/scripts/` directory.
- **Memory Management**: For the massive Engagement 5 datasets (approx. 1.0 TB uncompressed), the E5 scripts use a disk-based SQLite approach to bypass memory constraints.
- **OS Architecture Adaptation**: Windows (Marple) environments exhibit different log characteristics and entropy. The `phase1_E5_Marple.py` script specifically retrieves file paths from `predicateObjectPath` during edge generation to properly map relationships.
- **Schema Version**: When using Engagement 5 datasets, ensure that references to schema versions like `cdm18` are changed to `cdm20`.

### Phase 2: Feature Extraction & Node-set Construction (`phase2_feature_extraction/`)
- **NODLINK Integration**: This phase depends on the NODLINK framework (`[https://github.com/PKU-ASAL/Simulated-Data](https://github.com/PKU-ASAL/Simulated-Data)`). Place the phase2 scripts inside the simulated-data root directory and ensure intermediate files are stored in a `data` folder.
- **Activity Granularity**: The node-set size is set to `5`, explicitly optimized to balance context retention and semantic dilution.
- **Feature Vector**: The node-set feature vector is calculated as a weighted sum of command lines, file objects, and network flows.

### Phase 3: Similarity-based Labeling (`phase3_labeling/`)
- **Ground Truth**: This phase requires a malicious node list (`mal_uuid.txt`). Pre-extracted lists for each dataset are provided in the `ground_truth/` directory (e.g., `mal_uuid_E3.txt`). Copy or rename the appropriate file to `mal_uuid.txt` and place it in your working data directory before running. You can also use `tools/search.py` to search for Indicator of Compromise (IoC) strings from the DARPA Ground Truth reports.

### Phase 4: Similarity-based Graph Reduction (`phase4_reduction/`)
- Filters out frequent benign activities from the provenance graph.
- **Dynamic Similarity Thresholds**: The optimal threshold heavily depends on the OS. We recommend `0.95` for Linux (Theia) to achieve high reduction with minimal false negatives. For Windows (Marple), relax the threshold to `0.85` to absorb dynamic OS noise.
- Choose `phase4_memory.py` for smaller datasets or `phase4_disk.py` to utilize SQLite for large datasets.

### Utilities (`tools/`)
- Contains supplementary scripts for analyzing dataset distributions.
- **`cmdline_count.py` & `syscall_count.py`**: Count and output occurrence frequencies of command lines and event types. *Note: Change the target schema to `cdm18` for Engagement 3, and `cdm20` for Engagement 5 within the scripts*.

## Citation
If you use this code or our method in your research, please cite our ICICS 2026 paper:

```bibtex
@inproceedings{niwase2026benign,
  title={Benign Activity Filter: A Benign Activity Extraction Method for Efficient Provenance-based Log Analysis},
  author={Ryo Niwase and Taishin Saito and Kuniyasu Suzaki and Masaki Hashimoto},
  booktitle={The 28th International Conference on Information and Communications Security (ICICS 2026)},
  year={2026}
}
```
