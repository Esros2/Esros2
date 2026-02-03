import angr
import sys



import re

import subprocess
import re

import networkx as nx

from networkx.drawing.nx_agraph import write_dot, to_agraph
import pygraphviz as pgv
from datetime import datetime
import time
import pprint
import subprocess
import re
from collections import defaultdict




import re

failed = 0
detected = 0
total_ssyscall = 0
Global_Libc_Counts = {}
Global_Libc_Counts_ROS = {}


DoneSolve = {}
libDone = []
SolveDone = []
function_instructions = {}
function_dict = {}
plt_mappings = {}
SyscallCounter = {}
FunList = {}
address_to_func = {}
Indirect_Next = {}
function_boundaries = {}


class SysCallNode:
    def __init__(self,RawSyscall,RawSyscall_set,DynCall_List,DirectCall_List,TotalSyscall,Total_set):
        self.RawSyscall = RawSyscall
        self.DynCall_List = DynCall_List
        self.DirectCall_List = DirectCall_List
        self.TotalSyscall = TotalSyscall
        self.RawSyscall_set = RawSyscall_set
        self.Total_set = Total_set



numbers = [
    4, 5, 6, 21, 22, 27, 28, 36, 37, 39, 51, 52, 63, 75, 78, 79,89, 96, 97, 
    98, 99, 100, 102, 104, 107, 108, 110, 111, 115, 118, 120, 121, 124, 125, 
    136, 137, 138, 139, 140, 143, 145, 146, 147, 148, 162, 163, 164, 177, 178, 
    181, 186, 191, 192, 193, 194, 195, 196, 201, 204, 208, 211, 217, 221, 224, 
    225, 228, 229, 274, 282, 287, 298, 309, 315, 318, 332, 334, 440, 441
]

so_files = [

 # rosidl core runtime & type-support
    "librosidl_runtime_c.so",
    "librosidl_typesupport_cpp.so",
    "librosidl_typesupport_c.so",
    "librosidl_typesupport_fastrtps_cpp.so",
    "librosidl_typesupport_fastrtps_c.so",
    "librosidl_typesupport_introspection_cpp.so",
    "librosidl_typesupport_introspection_c.so",

    # core utils
    "librcutils.so",
    "librcpputils.so",
    "liblibstatistics_collector.so",

    # rcl (C) client libs
    "librcl.so",
    "librcl_action.so",
    "librcl_lifecycle.so",
    "librcl_yaml_param_parser.so",
    "librcl_logging_interface.so",
    "librcl_logging_spdlog.so",

    # rclcpp (C++)
    "librclcpp.so",
    "librclcpp_action.so",
    "librclcpp_lifecycle.so",

    # RMW abstraction + DDS wrappers
    "librmw.so",
    "librmw_implementation.so",
    "librmw_dds_common.so",
    "librmw_fastrtps_cpp.so",
    "librmw_fastrtps_shared_cpp.so",

    # infra
    "libament_index_cpp.so",
    "libclass_loader.so",
    "libcomponent_manager.so",

        "libfastcdr.so",
    "libfastcdr.so.1",
    "libfastcdr.so.1.0.24",
    "libfastrtps.so",
    "libfastrtps.so.2.6",
    "libfastrtps.so.2.6.8",
    "libfoonathan_memory-0.7.1.a",

        "librmw_cyclonedds_cpp.so",
    "librmw_connextdds.so",
    "librmw_gurumdds_cpp.so",
    "librosidl_runtime_cpp.so",
    "librosidl_typesupport_interface.so",
    "librcl_logging_noop.so",
    "librcl_components.so",


]



def merge_scc_nodes(G):
    sccs = list(nx.strongly_connected_components(G))
    
    for scc in sccs:
        if len(scc) < 2:
            continue  # Skip trivial SCCs

        # Build new merged label
        sorted_labels = sorted(scc)  # Sorting ensures deterministic order
        merged_label = "_".join(f"({lib},{addr})" for lib, addr in sorted_labels)

        # Sum attributes
        total_raw = sum(G.nodes[node].get('raw', 0) for node in scc)
        total_raw_set = set().union(*(G.nodes[node].get('raw_set', set()) for node in scc))
        total_raw_set_ros = set().union(*(G.nodes[node].get('raw_set_ros', set()) for node in scc))

        # print("total raw : ",total_raw)
        # Collect predecessors and successors not in the SCC
        preds = set()
        succs = set()
        for node in scc:
            preds.update(n for n in G.predecessors(node) if n not in scc)
            succs.update(n for n in G.successors(node) if n not in scc)

        # Remove original nodes
        G.remove_nodes_from(scc)

        # Add merged node
        G.add_node(merged_label, raw=total_raw, total=0,raw_set = total_raw_set, raw_set_ros = total_raw_set_ros, total_set = set(),total_set_ros = set())

        # Reconnect edges
        for p in preds:
            G.add_edge(p, merged_label)
        for s in succs:
            G.add_edge(merged_label, s)

    return G




def CreateGraphy(G, lib_dict, obj, label, visited):
    # print("yess : ",label)
    if label in visited:
        return

    visited.add(label)
    calls = obj['calls']

    for call in calls:
        # print(call)
        # Ensure call is a dictionary with one key-value pair
        func_name = call[0]
        # print("fun name : ",func_name)
        lib_name = call[1]
        lib_add = call[2]

        # func_name is like 'printf@plt', lib_name is now resolved like '/lib/x86...'
        # Split function and extract address
        func_key = (lib_name, lib_add)

        if lib_name not in lib_dict or lib_add not in lib_dict[lib_name]:
            continue  # skip unresolved

        if lib_name == '/lib/x86_64-linux-gnu/libc.so.6':
            continue

        # if os.path.basename(lib_name) in so_files:
        #     continue


        
        next_obj = lib_dict[lib_name][lib_add]
        next_label = (lib_name, lib_add)
        G.add_node(next_label,raw=next_obj['raw_libc_calls'],raw_set = next_obj['raw_set'] , raw_set_ros = next_obj['raw_set_ros'],  total=next_obj['total_libc_calls'],total_set = next_obj['total_set'],total_set_ros = next_obj['total_set_ros'] )
        G.add_edge(label, next_label)
        CreateGraphy(G, lib_dict, next_obj, next_label, visited)






def get_ldd_output(binary_path):
    try:
        # Run the ldd command on the binary
        result = subprocess.run(['ldd', binary_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if the command ran successfully
        if result.returncode == 0:
            return result.stdout
        else:
            ###print(f"Error running ldd: {result.stderr}")
            return None
    except Exception as e:
        ###print(f"Exception occurred: {e}")
        return None

# Function to extract shared library paths from the ldd output
def extract_shared_library_paths(ldd_output):
    if ldd_output:
        # Regular expression to extract the shared library paths
        lib_paths = re.findall(r'=>\s+(\S+)', ldd_output)
        return lib_paths
    return []


ans = set()
failed = {}
import re

def Solve(lib_name,func_add,func_info,lib_dict,plt_mappings):
    global failed
    ind = 0
    for call in func_info['calls']: 
        called_func = call[0]
        funLib = call[1]
        if funLib == 'plt':
            clean_func_name = called_func.split('@')[0]
            if clean_func_name in plt_mappings:
                maps = plt_mappings[clean_func_name]
                lib_dict[lib_name][func_add]['calls'][ind] = [called_func,maps[0],maps[1]]
                if maps[0] == '/lib/x86_64-linux-gnu/libc.so.6' and called_func not in whiteListed:
                    lib_dict[lib_name][func_add]['raw_libc_calls']+=1
                    lib_dict[lib_name][func_add]['raw_set'].add((maps[0],called_func))
                    if os.path.basename(lib_name) not in so_files:
                        lib_dict[lib_name][func_add]['raw_set_ros'].add((maps[0],called_func))
                    # lib_dict[lib_name][func_add]['raw_libc_calls'].add((map[0],clean_func_name))

                
            else :
                # print("not found  : ",called_func)
                if called_func in failed:
                    failed[called_func] +=1
                else :  
                    failed[called_func] = 1
        ind+=1

    return 






whiteListed = []
with open('whitelistedLibc.txt', 'r') as f:
    whiteListed = [line.strip() for line in f if line.strip()]


# Path to the file
file_path = "binaries.txt"                       

# Initialize an empty list
binary_paths = []

# Read the file and populate the listmain
with open(file_path, "r") as file:
    binary_paths = [line.strip() for line in file]



import csv
output_file = "withoutFilter.csv"




binaries = binary_paths




import os



def section_exists(binary, section_name):
    try:
        result = subprocess.run(['objdump', '-h', binary], capture_output=True, text=True, check=True)
        return section_name in result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Failed to check sections: {e}")
        return False



def fold_text_section(lines):
  
    cleaned = []
    first_addr = None
    disasm_idx = None

    func_hdr_re = re.compile(r"^[0-9a-fA-F]+\s+<.*>:$")
    insn_addr_re = re.compile(r"^\s*([0-9a-fA-F]+):")
    disasm_text_re = re.compile(r"^\s*Disassembly of section \.text:\s*$")

    for line in lines:
        stripped = line.strip()

        # Capture first instruction address
        m_addr = insn_addr_re.match(stripped)
        if m_addr and first_addr is None:
            first_addr = m_addr.group(1)

        # Skip actual function headers like "000000000040110 <main>:"
        if func_hdr_re.match(stripped):
            continue

        cleaned.append(line)

        # Remember where the ".text" disassembly line is
        if disasm_idx is None and disasm_text_re.match(stripped):
            disasm_idx = len(cleaned) - 1

    # Insert the fake ".text" header immediately after the disassembly header
    if disasm_idx is not None:
        addr_padded = (first_addr or "0").lower().zfill(16)   # e.g., 000000000005c100
        fake_hdr = f"{addr_padded} <.text>:"
        cleaned.insert(disasm_idx + 1, fake_hdr)

    return cleaned




tempcount = 0

with open(output_file, "w", newline="") as csvfile:

    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(["Packaage Name", "Libc Functions", "Libc Functions By App"])
    csvfile.flush()
    plt_mappings = {}
    # Global dictionary
    lib_dict = defaultdict(dict)
    
    for bin in binaries:
        binn = bin

    
        MyStack = []

        G = nx.DiGraph()  
        undef=0
        deff = 0
        dynamic = 0

        SystemCallMap = {}

        strace_failed = 0


        binn = bin
       


 


        libs = get_ldd_output(bin)

        lib_paths = re.findall(r'=>\s+(\S+)', libs)
        
        lib_paths.insert(0,bin)

        for lib_name in lib_paths:



            if lib_name in libDone:
                continue

            libDone.append(lib_name)

            if section_exists(lib_name,'.plt.sec'):
                result = subprocess.run(
                ["objdump","-d","-j",".plt.sec", lib_name],
                capture_output=True,
                text=True,
                check=True
            )

                lines = result.stdout.splitlines()
                got_mapping = {}

                current_func = None

                for line in lines:
                    func_decl = re.match(r'^\s*([0-9a-fA-F]+)\s+<([^>]+)>:', line)
                    if func_decl:
                        current_func = func_decl.group(2)
                        continue

                    if current_func and "jmp" in line and '<' in line:
                        # This is the jump to real implementation
                        match = re.search(r'<([^>]+)>', line)
                        if match:
                            resolved_func = match.group(1)
                            got_mapping[current_func] = resolved_func
                                                   
                            if '+' in resolved_func:
                                func = current_func.split('@')[0]
                                got_mapping[current_func] = func
   
                            current_func = None  # reset for next                  
           
            command = ["objdump", "-d", "--section=.text", lib_name]

            
            
            result = subprocess.run(command, capture_output=True, text=True)
            text_section = result.stdout    
            text_section_lines = result.stdout.splitlines()
            if lib_name == bin:  
                final_text = fold_text_section(text_section_lines)
            else :
                final_text = text_section_lines




            current_function = None
            current_function_addr = None

            for line in final_text:
                # if(lib_name == bin):
                #     print("line : ",line)
                func_match = re.match(r'^\s*([0-9a-fA-F]+)\s+<(.+)>:', line)
                if func_match:
                    address = func_match.group(1)
                    name = func_match.group(2)

                    # Close previous function
                    if current_function_addr:
                        lib_dict[lib_name][current_function_addr]['end_add'] = address

                    # Start new function
                    current_function = name
                    current_function_addr = address
                    lib_dict[lib_name][current_function_addr] = {
                        'calls': [],
                        'total_libc_calls': 0,
                        'raw_libc_calls': 0,
                        'total_set': set(),
                        'raw_set': set(),
                        'total_set_ros': set(),
                        'raw_set_ros': set(),
                        'function_name': current_function,
                        'start_add': current_function_addr,
                        'end_add': current_function_addr  # temporary, will be updated later
                    }

                else:
                    # Match instruction line
                    match = re.match(r'\s*([0-9a-fA-F]+):', line)
                    if match and current_function_addr:
                        address = match.group(1)
                        lib_dict[lib_name][current_function_addr]['end_add'] = address  # keeps updating

            current_function = None
            current_function_addr = None

            for line in final_text:   
                func_match = re.match(r'^\s*([0-9a-fA-F]+)\s+<(.+)>:', line)
                if func_match:
                    address = func_match.group(1)
                    name = func_match.group(2)
                    current_function = name
                    current_function_addr = address


                if current_function:
                    call_match = re.search(r'\bcall\s+([0-9a-fA-Fx]+)\s+<([^>]+)>', line)
                    if call_match:
                        called_addr = call_match.group(1)
                        called_func = call_match.group(2)

                        funLib = lib_name
                        if '@plt' in called_func:
                            
                            if called_func not in got_mapping:
                                if '+' in called_func:
                                    flag = 0
                                    match = re.search(r'call\s+([0-9a-fA-F]+)', line)
                                    if match:
                                        resolved_addr = match.group(1).lower()

                                        for func_addr, func_info in lib_dict[lib_name].items():
                                            start = int(func_info['start_add'], 16) if isinstance(func_info['start_add'], str) else func_info['start_add']
                                            end = int(func_info['end_add'], 16) if isinstance(func_info['end_add'], str) else func_info['end_add']
                                            resolved = int(resolved_addr, 16) if isinstance(resolved_addr, str) else resolved_addr
                                            # print("resolved:", hex(resolved), "start:", hex(start),"End : ",hex(end))

                                            if start <= resolved < end:
                                                flag = 1
                                                called_func = func_info['function_name']
                                                called_addr = f"{start:016x}"
                                                funLib = lib_name
                                                break  # optional: break if you only want the first match
                                    if not flag:
                                        tempcount+=1


                            else :
                                temp = got_mapping[called_func]
                                called_func = temp                                
                                funLib = 'plt'
                                called_addr = 0

                        elif '+' in called_func:
                            # Extract the resolved address (e.g., "4a510" from "call 4a510 <symbol>")
                            match = re.search(r'call\s+([0-9a-fA-F]+)', line)
                            if match:
                                resolved_addr = match.group(1).lower()

                                for func_addr, func_info in lib_dict[lib_name].items():
                                    start = int(func_info['start_add'], 16) if isinstance(func_info['start_add'], str) else func_info['start_add']
                                    end = int(func_info['end_add'], 16) if isinstance(func_info['end_add'], str) else func_info['end_add']
                                    resolved = int(resolved_addr, 16) if isinstance(resolved_addr, str) else resolved_addr

                                    if start <= resolved < end:
                                        called_func = func_info['function_name']
                                        called_addr = f"{start:016x}"
                                        funLib = lib_name
                                        break  # optional: break if you only want the first match
                       
                        clean_func_name = called_func.split('@')[0]
                    
                        lib_dict[lib_name][current_function_addr]['calls'].append(
                            [clean_func_name,funLib,called_addr]
                        )
    

            result = subprocess.run(
                ["objdump", "-T", lib_name],
                capture_output=True,
                text=True,
                check=True
            )

            for line in result.stdout.splitlines():
                match = re.match(r'^\s*([0-9a-fA-F]+)(?:\s+.*\s+)(\S+)$', line)
                if match:
                    address = match.group(1)
                    func_name = match.group(2)
                
                    # #print(func_name)
                    clean_func_name = func_name.split('@')[0]

                    # Skip symbols with address 0 (undefined symbols)
                    if int(address,16) == 0:
                        continue

                    # Use cleaned function name as key, map to (lib_name, address)
                    plt_mappings[clean_func_name] = (lib_name, address)
        
        main_add = 0

        for lib_name, functions in lib_dict.items():
            
            if lib_name  not in SolveDone:
                SolveDone.append(lib_name)
                for func_add, data in functions.items():
                    if lib_name == bin and data['function_name'] == 'main':
                        main_add = func_add

                    if lib_name == bin and data['function_name'] == '.text':
                        main_add = func_add
                        # print("whyy")
                                              
                    Solve(lib_name, func_add, data,lib_dict,plt_mappings)


        G = nx.DiGraph()
        
        label = (bin,main_add)
        G.add_node(label,raw = lib_dict[bin][main_add]['raw_libc_calls'], raw_set = lib_dict[bin][main_add]['raw_set'], raw_set_ros = lib_dict[bin][main_add]['raw_set_ros'], total = lib_dict[bin][main_add]['total_libc_calls'],
                   total_set = lib_dict[bin][main_add]['total_set'],total_set_ros = lib_dict[bin][main_add]['total_set_ros'] )
        visited = set()
        lib_infos = {}
        
        CreateGraphy(G,lib_dict,lib_dict[bin][main_add],label,visited)



        merge_scc_nodes(G)


        self_loops = list(nx.selfloop_edges(G))
        G.remove_edges_from(self_loops)
        print(G)
        visited = set()
        for node in reversed(list(nx.topological_sort(G))):
            total = G.nodes[node]['raw']  # Copy to avoid modifying raw directly
            total_set = G.nodes[node]['raw_set']
            total_set_ros = G.nodes[node]['raw_set_ros']

            # print("total from last : ",total)
            for succ in G.successors(node):
                total_set.update(G.nodes[succ]['total_set'])
                total_set_ros.update(G.nodes[succ]['total_set_ros'])         
   

            G.nodes[node]['total'] = total
            G.nodes[node]['total_set'] = total_set
            
            if os.path.basename(node[0]) not in so_files:
                # print("node so ifle me nahi hai ",node)
                G.nodes[node]['total_set_ros'] = total_set_ros
            else :
                # print("node so file me hai ",node)
                G.nodes[node]['total_set_ros'] = set()

 
        csvwriter.writerow([bin, len(G.nodes[node]['total_set']), len(G.nodes[node]['total_set_ros'])])
        csvfile.flush()


        for lib , fun in G.nodes[label]['total_set']:
            if fun in Global_Libc_Counts:
                Global_Libc_Counts[fun] +=1
            else :
                Global_Libc_Counts[fun] = 1
        
        for lib , fun in G.nodes[label]['total_set_ros']:
            if fun in Global_Libc_Counts_ROS:
                Global_Libc_Counts_ROS[fun] +=1
            else :
                Global_Libc_Counts_ROS[fun] = 1

import csv

with open("libc_counts.csv", "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Lib Name", "Count"])

    for lib, count in Global_Libc_Counts.items():
        writer.writerow([lib, count])

with open("libc_counts_ros.csv", "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Lib Name", "ROS Count"])

    for lib, count in Global_Libc_Counts_ROS.items():
        writer.writerow([lib, count])


with open("failed.csv", "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Fun Name", "Failed Count"])

    for lib, count in failed.items():
        writer.writerow([lib, count])


print(lib_dict)
