# # dedup_paths.py

# def extract_unique_paths(input_file="fclose.txt", output_file="Aakhri_fclose.txt"):
#     unique_paths = set()

#     # Read input file line by line
#     with open(input_file, "r") as infile:
#         for line in infile:
#             path = line.strip()
#             if path:  # skip empty lines
#                 unique_paths.add(path)

#     # Write unique paths into output file
#     with open(output_file, "w") as outfile:
#         for path in sorted(unique_paths):  # sorted for readability
#             outfile.write(path + "\n")

#     print(f"✅ Extracted {len(unique_paths)} unique paths into {output_file}")


# if __name__ == "__main__":
#     extract_unique_paths()


# # # extract_fgetc_paths.py

# def extract_unique_fgetc_paths(input_file="fgetc.txt", output_file="aakhri_fgetc.txt"):
#     unique_paths = set()

#     with open(input_file, "r") as infile:
#         for line in infile:
#             line = line.strip()
#             if "path=" in line:
#                 path = line.split("path=")[-1].strip()
#                 if path:
#                     unique_paths.add(path)

#     with open(output_file, "w") as outfile:
#         for path in sorted(unique_paths):
#             outfile.write(path + "\n")

#     print(f"✅ Extracted {len(unique_paths)} unique paths into {output_file}")


# if __name__ == "__main__":
#     extract_unique_fgetc_paths()



# # extract_fopen_paths.py

def extract_unique_fopen_entries(input_file="fopen.txt", output_file="aakhri_fopen.txt"):
    unique_entries = set()
    current_name = None
    current_mode = None

    with open(input_file, "r") as infile:
        for line in infile:
            line = line.strip()

            if line.startswith("name :"):
                current_name = line.split("name :")[-1].strip()

            elif line.startswith("mode :"):
                current_mode = line.split("mode :")[-1].strip()

                # ✅ save immediately when both are available
                if current_name and current_mode:
                    unique_entries.add((current_name, current_mode))
                    current_name, current_mode = None, None

    # Write results
    with open(output_file, "w") as outfile:
        for name, mode in sorted(unique_entries):
            outfile.write(f"{name}  mode={mode}\n")

    print(f"✅ Extracted {len(unique_entries)} unique fopen entries into {output_file}")


if __name__ == "__main__":
    extract_unique_fopen_entries()

# # extract_fgetc_paths.py

# def extract_unique_open_paths(input_file="open.txt", output_file="aakhri_open.txt"):
#     unique_paths = set()

#     with open(input_file, "r") as infile:
#         for line in infile:
#             line = line.strip()
#             if "pathname=" in line:   # ✅ fix here
#                 # take only before ", flags="
#                 path = line.split("pathname=")[-1].split(", flags=")[0].strip()
#                 if path:
#                     unique_paths.add(path)

#     with open(output_file, "w") as outfile:
#         for path in sorted(unique_paths):
#             outfile.write(path + "\n")

#     print(f"✅ Extracted {len(unique_paths)} unique paths into {output_file}")


# if __name__ == "__main__":
#     extract_unique_open_paths()


# # extract_read_libs.py

# def extract_unique_read_libs(input_file="read.txt", output_file="aakhri_read.txt"):
#     unique_libs = set()

#     with open(input_file, "r") as infile:
#         for line in infile:
#             line = line.strip()
#             if "->" in line:
#                 path = line.split("->")[-1].strip()
#                 if path:
#                     libname = path.split("/")[-1]  # take only the last part
#                     unique_libs.add(libname)

#     with open(output_file, "w") as outfile:
#         for lib in sorted(unique_libs):
#             outfile.write(lib + "\n")

#     print(f"✅ Extracted {len(unique_libs)} unique library names into {output_file}")


# if __name__ == "__main__":
#     extract_unique_read_libs()

# extract_fread_paths.py

# def extract_unique_fread_paths(input_file="fread.txt", output_file="aakhri_fread.txt"):
#     unique_paths = set()

#     with open(input_file, "r") as infile:
#         for line in infile:
#             line = line.strip()
#             if "path=" in line:
#                 path = line.split("path=")[-1].strip()
#                 if path:
#                     unique_paths.add(path)

#     with open(output_file, "w") as outfile:
#         for path in sorted(unique_paths):
#             outfile.write(path + "\n")

#     print(f"✅ Extracted {len(unique_paths)} unique fread paths into {output_file}")


# if __name__ == "__main__":
#     extract_unique_fread_paths()

# extract_fseeko64_paths.py

# def extract_unique_fseeko64_paths(input_file="ftello64.txt", output_file="aakhri_ftello64.txt"):
#     unique_paths = set()

#     with open(input_file, "r") as infile:
#         for line in infile:
#             line = line.strip()
#             if "path=" in line:
#                 path = line.split("path=")[-1].strip()
#                 if path:
#                     unique_paths.add(path)

#     with open(output_file, "w") as outfile:
#         for path in sorted(unique_paths):
#             outfile.write(path + "\n")

#     print(f"✅ Extracted {len(unique_paths)} unique fseeko64 paths into {output_file}")


# if __name__ == "__main__":
#     extract_unique_fseeko64_paths()

# extract_name_mode.py

# def extract_name_mode(input_file="fopen.txt", output_file="aakhri_fopen.txt"):
#     unique_entries = set()
#     current_name = None
#     current_mode = None

#     with open(input_file, "r") as infile:
#         for line in infile:
#             line = line.strip()

#             if line.startswith("name :"):
#                 current_name = line.split("name :")[-1].strip()

#             elif line.startswith("mode :"):
#                 current_mode = line.split("mode :")[-1].strip()

#                 # ✅ Save once both name and mode are captured
#                 if current_name and current_mode:
#                     unique_entries.add((current_name, current_mode))
#                     current_name, current_mode = None, None

#     # Write unique pairs to output file
#     with open(output_file, "w") as outfile:
#         for name, mode in sorted(unique_entries):
#             outfile.write(f"{name}  mode={mode}\n")

#     print(f"✅ Extracted {len(unique_entries)} unique (name, mode) pairs into {output_file}")


# if __name__ == "__main__":
#     extract_name_mode()
