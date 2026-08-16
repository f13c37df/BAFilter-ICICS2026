import time
import os
import os.path as osp
import re
import sqlite3
from datetime import datetime

def show(msg):
    print(msg + ' ' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

# Record script start time
start_time = datetime.now()

# ==========================================
# 1. Extract data and create file list
# ==========================================

# Note: Evaluation data extraction commands (6)
os.system('tar -zxvf /path/to/dataset/data_1.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_2.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_3.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_4.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_5.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_6.json.tar.gz')

# Target directory list
dir_list = [
    'data_1',
    'data_2',
    'data_3',
    'data_4',
    'data_5',
    'data_6',
]

# Create a list of JSON files
all_json_files = []
for target_dir in dir_list:
    if not osp.exists(target_dir):
        print(f"Directory not found : {target_dir}")
        continue
    
    # Recursively search within the directory
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            # Target files containing .json but not ending with .tar.gz or .txt
            if ".json" in file and not file.endswith(".tar.gz") and not file.endswith(".txt"):
                all_json_files.append(osp.join(root, file))

all_json_files.sort()
print(f"Total files to process: {len(all_json_files)}")

# ==========================================
# 2. Setup and preparation (Logic is the same latest version as for training)
# ==========================================

# --- Define regular expression patterns (robust version) ---
pattern_uuid = re.compile(r'\"uuid\"\s*:\s*\"(.*?)\"')
pattern_type = re.compile(r'\"type\"\s*:\s*\"(.*?)\"')
pattern_time = re.compile(r'\"timestampNanos\"\s*:\s*(.*?),')
pattern_filename = re.compile(r'\"filename\"\s*:\s*\"(.*?)\"')

pattern_src = re.compile(r'\"subject\"\s*:\s*\{\"com\.bbn\.tc\.schema\.avro\.cdm20\.UUID\"\s*:\s*\"(.*?)\"')
pattern_dst1 = re.compile(r'\"predicateObject\"\s*:\s*\{\"com\.bbn\.tc\.schema\.avro\.cdm20\.UUID\"\s*:\s*\"(.*?)\"')
pattern_dst2 = re.compile(r'\"predicateObject2\"\s*:\s*\{\"com\.bbn\.tc\.schema\.avro\.cdm20\.UUID\"\s*:\s*\"(.*?)\"')

# List of valid event types
valid_event_types = [
    "EVENT_EXECUTE", 
    "EVENT_CLONE",
    "EVENT_OPEN", 
    "EVENT_READ", 
    "EVENT_WRITE",
    "EVENT_RECVFROM", 
    "EVENT_SENDTO", 
    "EVENT_RECVMSG", 
    "EVENT_SENDMSG",
    "EVENT_MODIFY_FILE_ATTRIBUTES", 
    "EVENT_CREATE_OBJECT"
]

notice_num = 1000000

# Initialize counts
total_nodes = 0
total_edges = 0
total_netflow_nodes = 0
total_subject_nodes = 0
total_file_nodes = 0
total_filename_nodes = 0

# --- Prepare SQLite database ---
# Use a local temporary folder
db_path = "/tmp/nodemap.db"
if os.path.exists(db_path):
    os.remove(db_path)

conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS nodes (uuid text PRIMARY KEY, type text)''')
c.execute('PRAGMA synchronous = OFF')
conn.commit()

# Buffer for batch processing
db_buffer = []
BUFFER_SIZE = 100000

# ==========================================
# 3. Main processing loop
# ==========================================

with open("subject_info.txt", "w") as subject_info_file, \
     open("fileobject_info.txt", "w") as fileobject_info_file, \
     open("netflowobject_info.txt", "w") as netflowobject_info_file, \
     open("valid_edges_details.txt", "w") as valid_edges_details_file:
    
    for now_path in all_json_files:
        
        # 2-pass processing: Register all nodes to DB in Pass 1, create edges in Pass 2
        
        # --- Pass 1: Node registration ---
        for i in range(1):
            with open(now_path, 'r') as f:
                show(f"Pass 1 (Nodes): {now_path}")
                cnt = 0
                for line in f:
                    cnt += 1
                    if cnt % notice_num == 0: print(f"Node processing: {cnt}")
                    
                    # Skip unnecessary lines (keep the number of nodes appropriate with strict checks)
                    if 'com.bbn.tc.schema.avro.cdm20.Event' in line and '"type":"com.bbn.tc.schema.avro.cdm20.Event"' in line.replace(" ", ""): continue
                    if 'com.bbn.tc.schema.avro.cdm20.Host' in line: continue
                    if 'com.bbn.tc.schema.avro.cdm20.TimeMarker' in line: continue
                    if 'com.bbn.tc.schema.avro.cdm20.StartMarker' in line: continue
                    if 'com.bbn.tc.schema.avro.cdm20.UnitDependency' in line: continue
                    if 'com.bbn.tc.schema.avro.cdm20.EndMarker' in line: continue
                    
                    uuid_list = pattern_uuid.findall(line)
                    if len(uuid_list) == 0: continue
                    uuid = uuid_list[0]
                    
                    # Determine type
                    current_type = "Unknown"
                    subject_type_list = pattern_type.findall(line)
                    if len(subject_type_list) > 0:
                        current_type = subject_type_list[0]
                    
                    # Forced determination (prevent Unknown & prevent NetFlow omission)
                    if 'NetFlowObject' in line: current_type = 'NetFlowObject'
                    elif 'MemoryObject' in line: current_type = 'MemoryObject'
                    elif 'UnnamedPipeObject' in line: current_type = 'UnnamedPipeObject'
                    elif 'FileObject' in line or 'FILE_OBJECT' in line:
                         if 'FILE_OBJECT' not in str(current_type): current_type = 'FILE_OBJECT'
                    elif 'Subject' in line or 'SUBJECT' in line:
                         if 'SUBJECT' not in str(current_type).upper(): current_type = 'SUBJECT'

                    # Register buffer to DB
                    db_buffer.append((uuid, current_type))
                    if len(db_buffer) >= BUFFER_SIZE:
                        c.executemany("INSERT OR REPLACE INTO nodes VALUES (?, ?)", db_buffer)
                        conn.commit()
                        db_buffer = []
                        
                    # Write detailed information
                    if 'NetFlowObject' in current_type:
                        r_addr_search = re.search(r'\"remoteAddress\"\s*:\s*\{\s*\"string\"\s*:\s*\"(.*?)\"', line)
                        if not r_addr_search: r_addr_search = re.search(r'\"remoteAddress\"\s*:\s*\"(.*?)\"', line)
                        
                        r_port_search = re.search(r'\"remotePort\"\s*:\s*\{\s*\"int\"\s*:\s*(\d+)', line)
                        if not r_port_search: r_port_search = re.search(r'\"remotePort\"\s*:\s*(\d+)', line)
                        
                        r_addr_val = r_addr_search.group(1) if r_addr_search else 'N/A'
                        r_port_val = r_port_search.group(1) if r_port_search else 'N/A'
                        netflowobject_info_file.write(f"{uuid}, remoteAddress: {r_addr_val}, remotePort: {r_port_val}\n")

                    if 'Subject' in current_type or 'SUBJECT' in current_type:
                        total_subject_nodes += 1
                        cmd_line = re.search(r'\"cmdLine\"\s*:\s*\{\s*\"string\"\s*:\s*\"(.*?)\"', line)
                        if not cmd_line: cmd_line = re.search(r'\"cmdLine\"\s*:\s*\"(.*?)\"', line)
                        parent_subject = re.search(r'\"parentSubject\"\s*:\s*\{\"com\.bbn\.tc\.schema\.avro\.cdm20\.UUID\"\s*:\s*\"(.*?)\"', line)
                        cmd_val = cmd_line.group(1) if cmd_line else 'N/A'
                        parent_val = parent_subject.group(1) if parent_subject else 'N/A'
                        subject_info_file.write(f"{uuid}, cmdLine: {cmd_val}, parentSubject: {parent_val}\n")
                    
                    if 'FileObject' in current_type or 'FILE_OBJECT' in current_type:
                        total_file_nodes += 1
                        filename_search = re.search(r'\"filename\"\s*:\s*\{\s*\"string\"\s*:\s*\"(.*?)\"', line)
                        if not filename_search: filename_search = pattern_filename.search(line)
                        if filename_search:
                            fileobject_info_file.write(f"{uuid}, filename: {filename_search.group(1)}\n")
                            total_filename_nodes += 1

        # Write remaining buffer after Pass 1 completes
        if db_buffer:
            c.executemany("INSERT OR REPLACE INTO nodes VALUES (?, ?)", db_buffer)
            conn.commit()
            db_buffer = []

        # Retrieve counts from DB
        c.execute("SELECT count(*) FROM nodes")
        total_nodes = c.fetchone()[0]
        c.execute("SELECT count(*) FROM nodes WHERE type LIKE '%NetFlowObject%'")
        total_netflow_nodes = c.fetchone()[0]


        # --- Pass 2: Edge creation ---
        for i in range(1):
            with open(now_path, 'r') as f, open(now_path + '.txt', 'w') as fw:
                show(f"Pass 2 (Edges): {now_path}")
                cnt = 0
                for line in f:
                    cnt += 1
                    if cnt % notice_num == 0: print(f"Edge processing: {cnt}")

                    if 'com.bbn.tc.schema.avro.cdm20.Event' in line:
                        pattern_subj = re.compile(r'\"subject\"\s*:\s*\{\"com\.bbn\.tc\.schema\.avro\.cdm20\.UUID\"\s*:\s*\"(.*?)\"')
                        edgeType_list = pattern_type.findall(line)
                        if len(edgeType_list) == 0: continue
                        edgeType = edgeType_list[0]
                        timestamp_list = pattern_time.findall(line)
                        timestamp = timestamp_list[0] if timestamp_list else "0"
                        event_uuid_list = pattern_uuid.findall(line)
                        event_uuid = event_uuid_list[0] if event_uuid_list else "unknown"

                        srcId_list = pattern_subj.findall(line)
                        if len(srcId_list) == 0: continue
                        srcId = srcId_list[0]

                        # Retrieve source type from DB
                        c.execute("SELECT type FROM nodes WHERE uuid=?", (srcId,))
                        row = c.fetchone()
                        if row is None: continue 
                        srcType = row[0]

                        # Edge 1
                        dstId1_list = pattern_dst1.findall(line)
                        if len(dstId1_list) > 0 and dstId1_list[0] != 'null':
                            dstId1 = dstId1_list[0]
                            c.execute("SELECT type FROM nodes WHERE uuid=?", (dstId1,))
                            row = c.fetchone()
                            if row:
                                dstType1 = row[0]
                                this_edge1 = str(srcId) + '\t' + str(srcType) + '\t' + str(dstId1) + '\t' + str(dstType1) + '\t' + str(edgeType) + '\t' + str(timestamp) + '\n'
                                fw.write(this_edge1)
                                total_edges += 1
                                
                                if edgeType in valid_event_types:
                                    is_src_valid = any(s in srcType for s in ['NetFlowObject', 'Subject', 'SUBJECT', 'FileObject', 'FILE_OBJECT'])
                                    is_dst1_valid = any(s in dstType1 for s in ['NetFlowObject', 'Subject', 'SUBJECT', 'FileObject', 'FILE_OBJECT'])
                                    if is_src_valid and is_dst1_valid:
                                        valid_edges_details_file.write(f"Event UUID: {event_uuid}, EventType: {edgeType}, srcId: {srcId}, srcType: {srcType}, dstId1: {dstId1}, dstType1: {dstType1}\n")

                        # Edge 2
                        dstId2_list = pattern_dst2.findall(line)
                        if len(dstId2_list) > 0 and dstId2_list[0] != 'null' and '00000000-0000' not in dstId2_list[0]:
                            dstId2 = dstId2_list[0]
                            c.execute("SELECT type FROM nodes WHERE uuid=?", (dstId2,))
                            row = c.fetchone()
                            if row:
                                dstType2 = row[0]
                                this_edge2 = str(srcId) + '\t' + str(srcType) + '\t' + str(dstId2) + '\t' + str(dstType2) + '\t' + str(edgeType) + '\t' + str(timestamp) + '\n'
                                fw.write(this_edge2)
                                total_edges += 1

                                if edgeType in valid_event_types:
                                    is_src_valid = any(s in srcType for s in ['NetFlowObject', 'Subject', 'SUBJECT', 'FileObject', 'FILE_OBJECT'])
                                    is_dst2_valid = any(s in dstType2 for s in ['NetFlowObject', 'Subject', 'SUBJECT', 'FileObject', 'FILE_OBJECT'])
                                    if is_src_valid and is_dst2_valid:
                                        valid_edges_details_file.write(f"Event UUID: {event_uuid}, EventType: {edgeType}, srcId: {srcId}, srcType: {srcType}, dstId2: {dstId2}, dstType2: {dstType2}\n")

# Close DB connection
conn.close()
# Delete DB file (keep if necessary)
if os.path.exists(db_path):
    os.remove(db_path) 
os.system('rm data_*')

end_time = datetime.now()

print(f"Total nodes: {total_nodes}")
print(f"Total NetFlowObject nodes: {total_netflow_nodes}")
print(f"Total Subject nodes: {total_subject_nodes}")
print(f"Total FileObject nodes: {total_file_nodes}")
print(f"Total edges: {total_edges}")
print(f"Script execution time: {end_time - start_time}")