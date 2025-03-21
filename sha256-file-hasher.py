"""
SHA-256 File Hasher

This script calculates the SHA-256 hash of a given file and appends the hash 
information (timestamp, file name, and hash) to an output file.

Usage:
    python script.py <file_path>
    python script.py <file_path> -o <output_file>

Arguments:
    <file_path>   The path to the file to be hashed.
    -o, --output  (Optional) Specify the output file to store the hash (default: hash_log.txt).

Example:
    python script.py example.txt
    python script.py example.txt -o my_hashes.log
"""

import hashlib
import argparse
import os
from datetime import datetime

def calculate_sha256(file_path):
    """
    Calculates the SHA-256 hash of a given file.
    
    Args:
        file_path (str): Path to the file to be hashed.
    
    Returns:
        str: SHA-256 hash of the file in hexadecimal format.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Calculates the SHA-256 hash of a file and saves it to a log file.")
    parser.add_argument("file", help="Path to the file to be hashed")
    parser.add_argument("-o", "--output", help="Path to save the hash log (default: hash_log.txt)", default="hash_log.txt")
    args = parser.parse_args()

    try:
        # Compute the SHA-256 hash
        hash_result = calculate_sha256(args.file)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current date and time
        log_entry = f"{timestamp} | {os.path.basename(args.file)} | {hash_result}\n"

        # Append the hash info to the log file
        with open(args.output, "a") as f:
            f.write(log_entry)

        print(f"SHA-256: {hash_result}")
        print(f"Hash information saved to: {args.output}")
    except FileNotFoundError:
        print("Error: File not found.")
    except Exception as e:
        print(f"Error processing the file: {e}")
