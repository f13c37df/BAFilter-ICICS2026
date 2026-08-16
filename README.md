# BAFilter: Benign Activity Filter

This repository provides the official implementation of the Benign Activity Filter (BAFilter), a pre-processor designed for Efficient Provenance-based Log Analysis. It was accepted at the 28th International Conference on Information and Communications Security (ICICS 2026).

BAFilter aims to mitigate the "dependency explosion" problem in Data Provenance. It utilizes natural language processing (FastText) to vectorize activity content and removes frequently occurring benign activities based on cosine similarity, effectively shrinking the search space placed before a detector.

## Prerequisites
- **OS**: Ubuntu 22.04
- **Python**: 3.10.12
- **Dependencies**: `networkx`, `gensim`, `scikit-learn`, `numpy`, `openpyxl`, `matplotlib`, `nostril`

## Datasets
The scripts evaluate the DARPA Transparent Computing (TC) Dataset:
- Engagement 3 (Theia)
- Engagement 5 (Theia / Marple)

*Note: For Engagement 5, download the official `.bin` files and use `tools/bin2json.py` to convert them to `.json.tar.gz` format before processing.*

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
Extracts events and nodes (Subjects, FileObjects, NetFlowObjects) from raw JSON logs.
- **Memory Management**: For the massive Engagement 5 datasets (approx. 1.0 TB uncompressed), the E5 scripts use a disk-based SQLite approach to bypass memory constraints.
- **OS Architecture Adaptation**: Windows (Marple) environments exhibit different log characteristics and entropy. The `phase1_E5_Marple.py` script specifically retrieves file paths from `predicateObjectPath` during edge generation to properly map relationships.

### Phase 2: Feature Extraction & Node-set Construction (`phase2_feature_extraction/`)
Applies FastText to embed textual attributes and extracts context as fixed-length node-sets.
- **Activity Granularity**: The node-set size is set to `5`, explicitly optimized to balance context retention and semantic dilution.
- **Feature Vector**: The node-set feature vector is calculated as a weighted sum of command lines, file objects, and network flows.

### Phase 3: Similarity-based Labeling (`phase3_labeling/`)
Labels node-sets as benign or malicious using cosine similarity.
- **Ground Truth**: This phase requires a malicious node list (`mal_uuid.txt`). The pre-extracted lists for each dataset are provided in the `ground_truth/` directory (e.g., `mal_uuid_E3.txt`). Please copy or rename the appropriate file to `mal_uuid.txt` and place it in your working data directory before running. You can also use `tools/search.py` to search for Indicator of Compromise (IoC) strings from the DARPA Ground Truth reports.

### Phase 4: Similarity-based Graph Reduction (`phase4_reduction/`)
Filters out frequent benign activities from the provenance graph.
- **Dynamic Similarity Thresholds**: The optimal threshold heavily depends on the OS. We recommend `0.95` for Linux (Theia) to achieve high reduction with minimal false negatives. For Windows (Marple), relax the threshold to `0.85` to absorb dynamic OS noise.
- Choose `phase4_memory.py` for smaller datasets or `phase4_disk.py` to utilize SQLite for large datasets.

### Utilities (`tools/`)
Contains supplementary scripts for analyzing dataset distributions.
- **`cmdline_count.py` & `syscall_count.py`**: Count and output occurrence frequencies of command lines and event types. *Note: Change the target schema to `cdm18` for Engagement 3, and `cdm20` for Engagement 5 within the scripts.*

## Citation
If you use this code or our method in your research, please cite our ICICS 2026 paper:

@inproceedings{niwase2026benign,
  title={Benign Activity Filter: A Benign Activity Extraction Method for Efficient Provenance-based Log Analysis},
  author={Ryo Niwase and Taishin Saito and Kuniyasu Suzaki and Masaki Hashimoto},
  booktitle={The 28th International Conference on Information and Communications Security (ICICS 2026)},
  year={2026}
}