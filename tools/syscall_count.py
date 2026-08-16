import os
import json
from collections import Counter
import matplotlib.pyplot as plt

FOLDER_PATH = "C:/path/to/dataset"  # Folder path

def count_event_types(folder_path):
    event_type_counter = Counter()
    total_events = 0  # Count the total number of events

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            with open(file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    try:
                        data = json.loads(line)
                        event_type = data["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["type"]  # Change to "cdm20" when analyzing Engagement5 data, and "cdm18" for Engagement3 data
                        event_type_counter[event_type] += 1
                        total_events += 1
                    except (json.JSONDecodeError, KeyError):
                        continue

    # Calculate event types and their percentages
    event_percentages = {event: (count / total_events) * 100 for event, count in event_type_counter.items()}

    print("Event type aggregation results:")
    for event, percentage in event_percentages.items():
        print(f"{event}: {event_type_counter[event]} count(s) ({percentage:.2f}%)")

    return event_percentages

def plot_histogram(event_percentages):
    # Prepare histogram data
    labels = list(event_percentages.keys())
    percentages = list(event_percentages.values())

    # Create histogram
    plt.figure(figsize=(10, 6))
    plt.bar(labels, percentages, color='skyblue')
    plt.xlabel('Event Types', fontsize=14)
    plt.ylabel('Percentage (%)', fontsize=14)
    plt.title('Event Type Distribution', fontsize=16)
    plt.xticks(rotation=45, ha='right', fontsize=12)
    plt.tight_layout()

    plt.savefig("e5_event_histogram.png")


    # Display histogram
    plt.show()

if __name__ == "__main__":
    if os.path.isdir(FOLDER_PATH):
        event_percentages = count_event_types(FOLDER_PATH)
        plot_histogram(event_percentages)
    else:
        print(f"The specified folder path is invalid: {FOLDER_PATH}")