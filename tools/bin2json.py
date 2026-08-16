import os
import time
from datetime import datetime

start_time = datetime.now()

# Path to the directory containing dataset .bin files
bin_path = "/path/to/dataset"
dir_list = os.listdir(bin_path)
# print(len(dir_list))

for cur_file in dir_list:
    # Get the absolute path
    path = os.path.join(bin_path, cur_file)
    # print(path)
    command = "./json_consumer.sh " + path
    os.system(command)
    time.sleep(10)
    print("Successfully converted " + cur_file)

end_time = datetime.now()
print(f"Script execution time: {end_time - start_time}")