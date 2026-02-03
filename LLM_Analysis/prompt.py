import os
import json
import numpy as np

# Your folders and files
folder_path = "./"  # folder containing desc_*.txt
output_folder = "prompt_request"
embedding_file = "embeddings.json"  # embeddings for all functions
csv_file = "rag.csv"  # CSV containing previous classifications
top_k = 5  # number of similar examples to include

# Load embeddings
with open(embedding_file, "r", encoding="utf-8") as f:
    emb_data = json.load(f)

# Create dict of embeddings: {fn_name: np.array(embedding)}
emb_dict = {item["fn_name"]: np.array(item["embedding"]) for item in emb_data}

# Load CSV for previous classification
csv_dict = {}
with open(csv_file, "r", encoding="utf-8") as f:
    headers = f.readline().strip().split(",")
    for line in f:
        parts = line.strip().split(",")
        fn = parts[0]
        cats = [headers[i] for i, val in enumerate(parts) if i > 0 and val == "1"]
        csv_dict[fn] = cats

# Ensure output folder exists
os.makedirs(output_folder, exist_ok=True)

# Function to compute cosine similarity
def cosine_sim(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


# Original prompt
prompt = """
You are a classification assistant specialized in libc function analysis. Your task is to classify a given libc function into one or more of these categories:

- Process Control
- Device Management
- File Management
- Protection
- Information Maintenance
- Communication

Analyze the libc function ONLY if it calls a system call (directly or indirectly). If it does NOT call any system call, classify it as Non-classified.

You will be provided with:
1. The function name
2. Its man page description

Use your broader knowledge of the libc function’s behavior, documented use cases, and typical roles to determine its classification. Ask yourself:

- Could it be used for process control?
- Could it be used for file management?
- Could it be used for device management?
- Could it be used for protection?
- Could it be used for information maintenance?
- Could it be used for communication?

A function may belong to multiple categories. Consider **all possible use cases**, not just the most common one.  

Category definitions:

Process Control:
Any function that influences the lifecycle, execution, or behavior of a process or thread. This includes creating or terminating processes, allocating or managing memory and resources, synchronizing threads or processes, or modifying process attributes such as priority or scheduling.

Device Management:
Any function that interacts with hardware or virtual devices, including accessing, configuring, or controlling them. This includes operations on device files or low-level I/O that directly affects hardware behavior.

File Management:
Any function that creates, reads, writes, modifies, deletes, or queries files or directories. This includes operations on file descriptors and managing file-related metadata.

Protection:
Any function that actively manages or enforces security, permissions, or access control. This includes changing file or resource permissions, modifying user or group IDs, or enforcing process-level restrictions. Functions that only read or check these attributes without making changes are excluded.

Information Maintenance:
Any function that retrieves, monitors, or maintains system or process information without directly affecting execution. This includes obtaining system statistics, time, environment variables, or process state. Functions that only modify or control resources fall outside this category.

Communication:
Any function that enables interaction between processes or systems. This includes inter-process communication (IPC), networking, message passing, event notification, or signaling mechanisms.

---

Examples:

Function name: malloc  
Man page: "The malloc() function allocates size bytes and returns a pointer to the allocated memory. The memory is not initialized. If size is 0, then malloc() returns a unique pointer value that can later be successfully passed to free()."  

Output:  
Process Control  

Reason:  
Allocating memory directly affects a process’s execution environment by reserving memory resources for its use. This influences the process lifecycle and behavior, as memory is a fundamental resource for process operation.

---

Function name: fwrite  
Man page: "The function fread() reads n items of data, each size bytes long, from the stream pointed to by stream, storing them at the location given by ptr. The function fwrite() writes n items of data, each size bytes long, to the stream pointed to by stream, obtaining them from the location given by ptr. For nonlocking counterparts, see unlocked_stdio(3)."  

Output:  
File Management  
Communication  
Device Management   

Reason:  
File Management  
Writing data from memory to a regular file directly manipulates file contents, which is the core of file management operations.  

Communication  
Writing to pipes, FIFOs, or sockets sends data between processes or systems, serving a communication purpose.  

Device Management  
Writing to device files (such as /dev/ttyS0) sends data to hardware devices, which constitutes device interaction.  
---

Function name: dlopen  
Man page: "The function dlopen() loads the dynamic shared object (shared library) file named by the null-terminated string filename and returns an opaque 'handle' for the loaded object. This handle is employed with other functions in the dlopen API, such as dlsym(3), dladdr(3), dlinfo(3), and dlclose()."  

Output:  
Process Control  
File Management  

Reason:  
Process Control  
dlopen() directly affects a process’s execution environment by dynamically loading code into the process’s memory space. This modifies the process’s behavior at runtime because new functions and symbols become available, which can influence control flow and resource usage. Loading a library is part of managing the process’s lifecycle and execution context.

File Management  
dlopen() reads the dynamic library file from the filesystem in order to load it into memory. Accessing the library file constitutes file management because it involves reading a file’s contents and interpreting its metadata (symbols, relocation tables, etc.).

---

Function name: system  
Man page: "The system() library function behaves as if it used fork(2) to create a child process that executed the shell command specified in command using execl(3). system() returns after the command has been completed. During execution of the command, SIGCHLD will be blocked, and SIGINT and SIGQUIT are ignored in the calling process. If command is NULL, system() returns a status indicating whether a shell is available on the system."  

Output:  
Process Control  
File Management  
Device Management  
Protection  
Communication  
Information Maintenance  

Reason:  
Process Control  
system() forks a new child process and executes the shell. This directly affects the process lifecycle, execution, and resource usage.  

File Management  
Commands executed via system() can read, write, or modify files, indirectly enabling file operations.  

Device Management  
Commands executed via system() can interact with hardware or virtual devices, such as reading from /dev/sda or writing to /dev/ttyS0.  

Protection  
Commands executed via system() can invoke operations that modify process or memory protections, such as mprotect() or chmod.  

Communication  
Commands executed via system() can perform inter-process communication, network communication, or send signals to other processes.  

Information Maintenance  
Commands executed via system() can query system or process information, e.g., date, uptime, /proc files, or clock_gettime().


Function name: chmod
Man Page : [NOTE: This is a system call wrapper function] The  chmod() and fchmod() system calls change a files mode bits.	 (The file mode consists of the file permis‐ sion bits plus the set-user-ID, set-group-ID, and sticky bits.)	These system calls differ only	in  how	 the file is specified:

Output : 
Protection
File Management

Reason :

Protection:
chmod controls who can access or modify a file by changing its permission bits.
This fits the Protection definition: “manages security, permissions, or access control.”
Even if the file is a device file, changing permissions only affects access, not the device behavior itself.

File Management:
chmod modifies metadata of the file (the mode bits).
This fits File Management, because altering file metadata is part of managing file-related information.

Not included categories:

Device Management: No direct interaction with the hardware. Permissions alone do not control or access the device.

Process Control: Doesn’t influence process lifecycle or execution.

Information Maintenance: Doesn’t provide system/process info.

Communication: Doesn’t send or receive data between processes.

---
Instructions:
For each function, carefully refer to the category definitions above. Only assign a category if the function behavior truly matches the definition.
Output only the matching category names, one per line. Do not include reasons, explanations, or additional text.

"""

# Filter embeddings to only functions present in CSV (manual classifications)
manual_emb_dict = {fn: emb for fn, emb in emb_dict.items() if fn in csv_dict}

for filename in os.listdir(folder_path):
    if filename.startswith("desc_") and filename.endswith(".txt"):
        fn_name = filename[len("desc_"):-len(".txt")]

        # Load the function description
        with open(os.path.join(folder_path, filename), "r", encoding="utf-8") as f:
            file_content = f.read()

        # Build dynamic examples from top-k similar functions (only from manual classifications)
        examples_text = ""
        if fn_name in emb_dict:
            sims = []
            for other_fn, emb in manual_emb_dict.items():
                if other_fn == fn_name:
                    continue
                sims.append((other_fn, cosine_sim(emb_dict[fn_name], emb)))
            sims.sort(key=lambda x: x[1], reverse=True)
            top_fns = [x[0] for x in sims[:top_k]]

            for ex_fn in top_fns:
                desc_path = os.path.join(folder_path, f"desc_{ex_fn}.txt")
                if os.path.exists(desc_path):
                    with open(desc_path, "r", encoding="utf-8") as f:
                        ex_desc = f.read()
                    ex_cats = ", ".join(csv_dict.get(ex_fn, []))
                    examples_text += f"\nFunction name: {ex_fn}\nMan page: {ex_desc}\nOutput: {ex_cats}\n---\n"

        # Prepare system message with appended dynamic examples
        system_message = {
            "role": "system",
            "content": prompt + ("\n\n---\nAdditional examples from similar functions:" + examples_text
                                if examples_text else "")
        }

        # Prepare the user message
        user_message = {
            "role": "user",
            "content": f"Here you can find man page description of libc function : {fn_name}\n\n{file_content}"
        }

        # Save as JSON
        messages = [system_message, user_message]
        json_path = os.path.join(output_folder, f"{fn_name}.json")
        with open(json_path, "w", encoding="utf-8") as out_file:
            json.dump(messages, out_file, ensure_ascii=False, indent=2)

        print(f"Created: {json_path}")

print("All prompt request JSON files are ready with dynamic RAG examples (filtered by manual classifications).")