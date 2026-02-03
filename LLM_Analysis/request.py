import json
import openai
import csv
import os
from collections import Counter
import time
openai.api_key = "#"

# Categories and CSV headers
categories = [
    "Process Control",
    "Device management",
    "File management",
    "Protection",
    "Information maintenance",
    "Communication",
    "Non-classified"
]
csv_headers = ["Function name"] + categories
csv_filename = "libc_classification.csv"

# Check if CSV file exists and is empty
file_exists = os.path.isfile(csv_filename)
file_empty = True
if file_exists:
    file_empty = os.path.getsize(csv_filename) == 0

flag = 0

# Get all .json files and sort lexicographically
json_files = sorted([f for f in os.listdir(".") if f.endswith(".json")])

# Open CSV file once in append mode
with open(csv_filename, mode="a", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    
    # Write headers if file is new or empty
    if not file_exists or file_empty:
        writer.writerow(csv_headers)

    # Process each JSON file one by one
    for filename in json_files:
        fn_name = os.path.splitext(filename)[0]
        print(f"Processing function: {fn_name}")

        # Start processing only after a specific function if needed
        if fn_name == 'vfprintf':
            flag = 1
        if flag == 0:
            continue

        # Load messages from JSON file
        with open(filename, "r", encoding="utf-8") as f:
            messages = json.load(f)

        # Call the OpenAI API 5 times and collect results
        responses = []
        for i in range(5):
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0,
                max_tokens=256,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0
            )
            content = response.choices[0].message.content
            print(f"Response {i+1} for {fn_name}:\n{content}\n")
            responses.append(content)
            print(response)
        
        # Count how many times each category appeared
        category_counts = Counter()
        for resp in responses:
            for cat in categories:
                if cat.lower() in resp.lower():
                    category_counts[cat] += 1

        # Only include categories appearing in the majority of responses (>=3)
        majority_categories = {cat: 1 if category_counts[cat] >= 3 else 0 for cat in categories}

        # Write row to CSV
        row = [fn_name] + [majority_categories[cat] for cat in categories]
        writer.writerow(row)
        time.sleep(3)  

print(f"Classification done for all JSON files. Results saved to {csv_filename}")
