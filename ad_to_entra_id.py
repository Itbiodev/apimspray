import os

# Define the file paths and your new domain
input_file = "libertad.com.mx-users-pass.txt"
output_file = "entra-libertad.com.mx-users-pass.txt"
new_domain = "@libertad.com.mx"

# Check if the input file exists before running
if not os.path.exists(input_file):
    print(f"Error: {input_file} not found. Please place it in this directory.")
    exit(1)

with open(input_file, "r", encoding="utf-8") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:
    
    for line in infile:
        # Strip whitespace and Windows carriage returns (\r\n)
        clean_line = line.strip()
        if not clean_line:
            continue
            
        try:
            # 1. Split 'domain.local\name:pass' at the backslash to remove the domain
            _, rest = clean_line.split("\\", 1)
            
            # 2. Split 'name:pass' at the first colon
            name, password = rest.split(":", 1)
            
            # 3. Write the new format: name@anotherdomain.com:pass
            outfile.write(f"{name}{new_domain}:{password}\n")
            
        except ValueError:
            # Skip lines that don't match the expected format
            print(f"Skipping malformed line: {clean_line}")

print(f"Success! Converted data saved to {output_file}")
