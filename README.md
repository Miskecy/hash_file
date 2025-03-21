# SHA-256 File Hasher
A simple Python script to compute the **SHA-256 hash** of a file and log it to a file, **without overwriting previous entries**.  
Each log entry includes the **timestamp, file name, and hash value**.

## Features
- Calculates **SHA-256 hash** of a given file
- **Appends** hash results to a log file instead of overwriting
- Stores **timestamp, file name, and hash**
- Allows specifying a custom output log file
- **GUI applications** available for drag-and-drop functionality:
  - **File Hasher GUI**: Generate and log hashes by dragging files
  - **Hash Verifier GUI**: Verify file integrity against previously logged hashes

## Installation
Ensure you have Python **3.7+** installed, then clone the repository:
```bash
git clone https://github.com/yourusername/sha256-file-hasher.git
cd sha256-file-hasher
```

For the GUI applications, you'll need the tkinterdnd2 library for drag-and-drop support:
```bash
pip install tkinterdnd2
```

## Command-Line Usage
Run the script with a file path as an argument:
```bash
python sha256-file-hasher.py <file_path>
```

### Optional Arguments:
| Argument | Description | Default |
|----------|-------------|---------|
| `<file_path>` | The path to the file to hash | Required |
| `-o, --output <log_file>` | Path to save hash log | hash_log.txt |

### Examples:
Hash a file and save to default log (hash_log.txt):
```bash
python sha256-file-hasher.py myfile.txt
```
Specify a custom output file for logging:
```bash
python sha256-file-hasher.py myfile.txt -o my_hashes.log
```

## GUI Applications

### File Hasher GUI
A graphical interface for hashing files with drag-and-drop functionality.

**Features:**
- Drag and drop multiple files to hash them at once
- Select output log file location
- View hashing results in real-time
- Process files in background to keep interface responsive

**Usage:**
```bash
python sha256-file-hasher-GUI.py
```

### Hash Verifier GUI
A tool to verify if files have been modified by comparing current hashes with previously recorded hashes.

**Features:**
- Load hash records from log files
- Drag and drop files to verify their integrity
- Color-coded results showing matches and modifications
- Detailed comparison of stored vs. current hashes
- Summary statistics of verification results

**Usage:**
```bash
python sha256-file-hasher-verifier-GUI.py
```

## Example Output in hash_log.txt
```
2025-03-21 14:30:00 | example.txt | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2025-03-21 14:32:15 | document.pdf | f5d1278e8109edd94e1e4197e04873b31b99973cfb2fd0c433ea9139e16522bd
```

## Dependencies
This script uses Python's built-in modules:
- hashlib – for SHA-256 hashing
- argparse – for command-line arguments
- datetime – for timestamps
- os – for handling file paths
- tkinter – for GUI applications
- threading – for background processing in GUI applications

Additional dependencies for GUI applications:
- tkinterdnd2 – for drag-and-drop functionality (optional but recommended)

## License
This project is licensed under the MIT License. Feel free to use, modify, and share!

## Contributing
Pull requests are welcome! If you find any issues or have suggestions, feel free to open an issue.

---
Happy Hashing! 🚀
