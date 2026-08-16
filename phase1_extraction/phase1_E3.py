import time
import os
import os.path as osp
import re
from datetime import datetime

def show(msg):
    print(msg + ' ' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

# Record script start time
start_time = datetime.now()


# Commands to extract archives
os.system('tar -zxvf /path/to/dataset/data_1.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_2.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_3.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_4.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_5.json.tar.gz')
os.system('tar -zxvf /path/to/dataset/data_6.json.tar.gz')


dir_list = ['data_1', 'data_2', 'data_3', 'data_4', 'data_5', 'data_6']

# Define regular expression patterns
pattern_uuid = re.compile(r'uuid\":\"(.*?)\"')
pattern_src = re.compile(r'subject\":{\"com.bbn.tc.schema.avro.cdm20.UUID\":\"(.*?)\"}')
pattern_dst1 = re.compile(r'predicateObject\":{\"com.bbn.tc.schema.avro.cdm20.UUID\":\"(.*?)\"}')
pattern_dst2 = re.compile(r'predicateObject2\":{\"com.bbn.tc.schema.avro.cdm20.UUID\":\"(.*?)\"}')
pattern_type = re.compile(r'type\":\"(.*?)\"')
pattern_time = re.compile(r'timestampNanos\":(.*?),')
pattern_filename = re.compile(r'\"filename\":\"(.*?)\"')

# List of valid event types
valid_event_types = [
    #"EVENT_MMAP", 
    #"EVENT_MPROTECT", 
    #"EVENT_BOOT", 
    "EVENT_EXECUTE", 
    "EVENT_CLONE",
    "EVENT_OPEN", 
    #"EVENT_CONNECT", 
    #"EVENT_UNLINK", 
    "EVENT_READ", 
    "EVENT_WRITE",
    "EVENT_RECVFROM", 
    "EVENT_SENDTO", 
    "EVENT_RECVMSG", 
    "EVENT_SENDMSG",
    #"EVENT_READ_SOCKET", 
    #"EVENT_WRITE_SOCKET", 
    "EVENT_MODIFY_FILE_ATTRIBUTES", 
    "EVENT_CREATE_OBJECT"
    #"EVENT_SHM"
]

notice_num = 1000000

# Initialize node and edge counts
total_nodes = 0
total_edges = 0
total_netflow_nodes = 0
total_subject_nodes = 0
total_file_nodes = 0
total_filename_nodes = 0
total_other_events = 0

all_json_files = []
for target_dir in dir_list:
    if not osp.exists(target_dir):
        print(f"Directory not found : {target_dir}")
        continue
 
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if ".json" in file and not file.endswith(".tar.gz") and not file.endswith(".txt"):
                all_json_files.append(osp.join(root, file))
all_json_files.sort()

with open("subject_info.txt", "w") as subject_info_file, \
     open("fileobject_info.txt", "w") as fileobject_info_file, \
     open("netflowobject_info.txt", "w") as netflowobject_info_file, \
     open("valid_edges_details.txt", "w") as valid_edges_details_file:
    
    for i in range(1):
        id_nodetype_map = {}
        for now_path in all_json_files :
            with open(now_path, 'r') as f:
                show(now_path)
                cnt = 0
                for line in f:
                    cnt += 1
                    if cnt % notice_num == 0:
                        print(cnt)
                    if 'com.bbn.tc.schema.avro.cdm20.Event' in line or 'com.bbn.tc.schema.avro.cdm20.Host' in line: continue
                    if 'com.bbn.tc.schema.avro.cdm20.TimeMarker' in line or 'com.bbn.tc.schema.avro.cdm20.StartMarker' in line: continue
                    if 'com.bbn.tc.schema.avro.cdm20.UnitDependency' in line or 'com.bbn.tc.schema.avro.cdm20.EndMarker' in line: continue
                    if len(pattern_uuid.findall(line)) == 0: print(line)
                    uuid = pattern_uuid.findall(line)[0]
                    subject_type = pattern_type.findall(line)

                    if len(subject_type) < 1:
                        if 'com.bbn.tc.schema.avro.cdm20.MemoryObject' in line:
                            id_nodetype_map[uuid] = 'MemoryObject'
                            continue
                        if 'com.bbn.tc.schema.avro.cdm20.NetFlowObject' in line:
                            id_nodetype_map[uuid] = 'NetFlowObject'
                            remote_address = re.search(r'"remoteAddress":"(.*?)"', line)
                            remote_port = re.search(r'"remotePort":(.*?),', line)
                            netflowobject_info_file.write(f"{uuid}, remoteAddress: {remote_address.group(1) if remote_address else 'N/A'}, remotePort: {remote_port.group(1) if remote_port else 'N/A'}\n")
                            continue
                        if 'com.bbn.tc.schema.avro.cdm20.UnnamedPipeObject' in line:
                            id_nodetype_map[uuid] = 'UnnamedPipeObject'
                            continue

                    id_nodetype_map[uuid] = subject_type[0]

                    if 'SUBJECT' in subject_type[0]:
                        total_subject_nodes += 1
                        cmd_line = re.search(r'\"cmdLine\":{\"string\":\"(.*?)\"}', line)
                        parent_subject = re.search(r'\"parentSubject\":{\"com.bbn.tc.schema.avro.cdm20.UUID\":\"(.*?)\"}', line)
                        subject_info_file.write(f"{uuid}, cmdLine: {cmd_line.group(1) if cmd_line else 'N/A'}, parentSubject: {parent_subject.group(1) if parent_subject else 'N/A'}\n")
                    if 'FILE_OBJECT' in subject_type[0]:
                        total_file_nodes += 1
                        filename = pattern_filename.search(line)
                        if filename:
                            fileobject_info_file.write(f"{uuid}, filename: {filename.group(1)}\n")
                            total_filename_nodes += 1

        total_nodes += len(id_nodetype_map)
        netflow_nodes = {k: v for k, v in id_nodetype_map.items() if v == 'NetFlowObject'}
        total_netflow_nodes += len(netflow_nodes)

        not_in_cnt = 0
        for now_path in all_json_files:
            with open(now_path, 'r') as f, open(now_path + '.txt', 'w') as fw:
                cnt = 0
                for line in f:
                    cnt += 1
                    if cnt % notice_num == 0:
                        print(cnt)

                    if 'com.bbn.tc.schema.avro.cdm20.Event' in line:
                        pattern = re.compile(r'subject\":{\"com.bbn.tc.schema.avro.cdm20.UUID\":\"(.*?)\"}')
                        edgeType = pattern_type.findall(line)[0]
                        timestamp = pattern_time.findall(line)[0]
                        event_uuid = pattern_uuid.findall(line)[0]  # Get Event UUID
                        srcId = pattern_src.findall(line)
                        if len(srcId) == 0: continue
                        srcId = srcId[0]
                        if not srcId in id_nodetype_map.keys():
                            not_in_cnt += 1
                            continue
                        srcType = id_nodetype_map[srcId]
                        dstId1 = pattern_dst1.findall(line)
                        if len(dstId1) > 0 and dstId1[0] != 'null':
                            dstId1 = dstId1[0]
                            if not dstId1 in id_nodetype_map.keys():
                                not_in_cnt += 1
                                continue
                            dstType1 = id_nodetype_map[dstId1]
                            this_edge1 = str(srcId) + '\t' + str(srcType) + '\t' + str(dstId1) + '\t' + str(dstType1) + '\t' + str(edgeType) + '\t' + str(timestamp) + '\n'
                            fw.write(this_edge1)
                            total_edges += 1

                            # Check valid edge details for valid event types
                            if edgeType in valid_event_types and any(substr in srcType for substr in ['NetFlowObject', 'SUBJECT', 'FILE_OBJECT']) and any(substr in dstType1 for substr in ['NetFlowObject', 'SUBJECT', 'FILE_OBJECT']):
                                valid_edges_details_file.write(f"Event UUID: {event_uuid}, EventType: {edgeType}, srcId: {srcId}, srcType: {srcType}, dstId1: {dstId1}, dstType1: {dstType1}\n")

                        dstId2 = pattern_dst2.findall(line)
                        if len(dstId2) > 0 and dstId2[0] != 'null' and dstId2[0] != '00000000-0000-0000-0000-000000000000':
                            dstId2 = dstId2[0]
                            if not dstId2 in id_nodetype_map.keys():
                                not_in_cnt += 1
                                continue
                            dstType2 = id_nodetype_map[dstId2]
                            this_edge2 = str(srcId) + '\t' + str(srcType) + '\t' + str(dstId2) + '\t' + str(dstType2) + '\t' + str(edgeType) + '\t' + str(timestamp) + '\n'
                            fw.write(this_edge2)
                            total_edges += 1

                            # Check valid edge details for valid event types
                            if edgeType in valid_event_types and any(substr in srcType for substr in ['NetFlowObject', 'SUBJECT', 'FILE_OBJECT']) and any(substr in dstType2 for substr in ['NetFlowObject', 'SUBJECT', 'FILE_OBJECT']):
                                valid_edges_details_file.write(f"Event UUID: {event_uuid}, EventType: {edgeType}, srcId: {srcId}, srcType: {srcType}, dstId2: {dstId2}, dstType2: {dstType2}\n")

# Remove temporary files
os.system('rm data_*')

# Record script end time
end_time = datetime.now()

# Output total numbers of nodes and edges
print(f"Total nodes: {total_nodes}")
print(f"Total NetFlowObject nodes: {total_netflow_nodes}")
print(f"Total Subject nodes: {total_subject_nodes}")
print(f"Total FileObject nodes: {total_file_nodes}")
print(f"Total edges: {total_edges}")

# Output execution time
print(f"Script execution time: {end_time - start_time}")