import os
import json
from collections import Counter

# Specify the input folder path
FOLDER_PATH = "C:/path/to/dataset"  # Folder path to be processed
OUTPUT_FILE = "C:/path/to/dataset/unique_cmdline_path_with_count.txt"  # Output file name

def extract_unique_cmdline_and_path_with_count(folder_path, output_file):
    cmdline_counter = Counter()  # Count the occurrences of cmdLine
    total_cmdline_count = 0      # Total occurrences of cmdLine

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    for line in file:
                        try:
                            # Parse JSON
                            data = json.loads(line)
                            subject = data.get("datum", {}).get("com.bbn.tc.schema.avro.cdm20.Subject", {}) # Change to "cdm20" when analyzing Engagement5 data, and "cdm18" for Engagement3 data
                            
                            # Get cmdLine
                            cmdline = subject.get("cmdLine", {}).get("string")
                            if cmdline:
                                cmdline_counter[cmdline] += 1
                                total_cmdline_count += 1
                        except (json.JSONDecodeError, KeyError, AttributeError) as e:
                            continue
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue

    # Save the results to a file
    try:
        with open(output_file, 'w', encoding='utf-8') as out_file:
            out_file.write("Unique cmdLine with counts and percentages:\n")
            for cmdline, count in cmdline_counter.most_common():
                percentage = (count / total_cmdline_count) * 100
                out_file.write(f"{cmdline}: {count} ({percentage:.2f}%)\n")

        print(f"Unique cmdLine along with their counts and percentages have been saved to {output_file}.")

    except Exception as e:
        print(f"Error writing to output file {output_file}: {e}")

# Main function
if __name__ == "__main__":
    if os.path.isdir(FOLDER_PATH):
        extract_unique_cmdline_and_path_with_count(FOLDER_PATH, OUTPUT_FILE)
    else:
        print(f"The specified folder path is invalid: {FOLDER_PATH}")