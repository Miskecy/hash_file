import hashlib
import os
import sys
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from datetime import datetime
import threading
import re

class HashVerifierGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-256 Hash Verifier")
        self.root.geometry("700x550")
        self.root.minsize(600, 450)
        
        # Store loaded hashes
        self.hash_records = {}
        
        # Set up the main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log file selection
        log_frame = ttk.Frame(main_frame)
        log_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(log_frame, text="Hash Log File:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.log_file = tk.StringVar(value="hash_log.txt")
        log_entry = ttk.Entry(log_frame, textvariable=self.log_file, width=40)
        log_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_button = ttk.Button(log_frame, text="Browse", command=self.browse_log_file)
        browse_button.pack(side=tk.LEFT, padx=(0, 5))
        
        load_button = ttk.Button(log_frame, text="Load Hashes", command=self.load_hash_log)
        load_button.pack(side=tk.RIGHT)
        
        # Hash records summary
        self.hash_info = tk.StringVar(value="No hash records loaded")
        hash_info_label = ttk.Label(main_frame, textvariable=self.hash_info)
        hash_info_label.pack(fill=tk.X, pady=(0, 10))
        
        # Drop zone
        drop_frame = ttk.LabelFrame(main_frame, text="Drop Files Here to Verify")
        drop_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.drop_area = tk.Text(drop_frame, height=5, background="#f0f0f0", font=("TkDefaultFont", 10))
        self.drop_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.drop_area.insert(tk.END, "Drag and drop files here to verify their SHA-256 hashes")
        self.drop_area.configure(state="disabled")
        
        # Make the drop area accept dropped files
        self.drop_area.drop_target_register("DND_Files")
        self.drop_area.dnd_bind("<<Drop>>", self.drop_files)
        
        # Browse button alternative
        browse_files_button = ttk.Button(main_frame, text="Or Select Files to Verify", command=self.browse_files)
        browse_files_button.pack(pady=(0, 10))
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Verification Results")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=12)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Load a hash log file to begin")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initialize progress bar (hidden initially)
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        
    def browse_log_file(self):
        file_path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")],
            initialfile=self.log_file.get()
        )
        if file_path:
            self.log_file.set(file_path)
            self.load_hash_log()
    
    def load_hash_log(self):
        log_path = self.log_file.get()
        if not os.path.exists(log_path):
            self.update_status(f"Error: Hash log file '{log_path}' not found")
            return
        
        try:
            self.hash_records = {}
            with open(log_path, "r") as f:
                for line in f:
                    # Parse line format: "YYYY-MM-DD HH:MM:SS | filename | hash"
                    match = re.match(r'(.+?) \| (.+?) \| ([a-fA-F0-9]+)', line.strip())
                    if match:
                        timestamp, filename, hash_value = match.groups()
                        self.hash_records[filename] = {
                            'timestamp': timestamp,
                            'hash': hash_value
                        }
            
            record_count = len(self.hash_records)
            self.hash_info.set(f"Loaded {record_count} hash records from {os.path.basename(log_path)}")
            self.update_status(f"Successfully loaded {record_count} hash records")
            
            # Clear previous results
            self.results_text.configure(state=tk.NORMAL)
            self.results_text.delete(1.0, tk.END)
            self.results_text.configure(state=tk.DISABLED)
            
        except Exception as e:
            self.update_status(f"Error loading hash log: {str(e)}")
    
    def browse_files(self):
        if not self.hash_records:
            self.update_status("Please load a hash log file first")
            return
            
        file_paths = filedialog.askopenfilenames(
            title="Select Files to Verify",
            filetypes=[("All files", "*.*")]
        )
        if file_paths:
            self.process_files(file_paths)
    
    def drop_files(self, event):
        if not self.hash_records:
            self.update_status("Please load a hash log file first")
            return
            
        file_paths = event.data
        # Convert from Tkinter's format to list of paths
        if isinstance(file_paths, str):
            file_paths = self.root.splitlist(file_paths)
        self.process_files(file_paths)
    
    def process_files(self, file_paths):
        # Show progress bar
        self.progress.pack(fill=tk.X, pady=(0, 10))
        self.progress.start(10)
        self.update_status(f"Verifying {len(file_paths)} file(s)...")
        
        # Process files in a separate thread to keep GUI responsive
        thread = threading.Thread(target=self.verify_files, args=(file_paths,))
        thread.daemon = True
        thread.start()
    
    def verify_files(self, file_paths):
        results = []
        
        for file_path in file_paths:
            try:
                filename = os.path.basename(file_path)
                
                # Check if file exists in hash records
                if filename not in self.hash_records:
                    results.append({
                        'filename': filename,
                        'status': 'NOT FOUND',
                        'message': f"No hash record found for {filename}"
                    })
                    continue
                
                # Calculate current hash
                current_hash = self.calculate_sha256(file_path)
                
                # Compare with stored hash
                stored_hash = self.hash_records[filename]['hash']
                timestamp = self.hash_records[filename]['timestamp']
                
                if current_hash == stored_hash:
                    results.append({
                        'filename': filename,
                        'status': 'MATCH',
                        'message': f"Hash verified: {filename} matches record from {timestamp}",
                        'hash': current_hash
                    })
                else:
                    results.append({
                        'filename': filename,
                        'status': 'MODIFIED',
                        'message': f"WARNING: {filename} has been modified since {timestamp}",
                        'stored_hash': stored_hash,
                        'current_hash': current_hash
                    })
                    
            except Exception as e:
                results.append({
                    'filename': os.path.basename(file_path),
                    'status': 'ERROR',
                    'message': f"Error processing {os.path.basename(file_path)}: {str(e)}"
                })
        
        # Update UI on the main thread
        self.root.after(0, self.update_results, results)
    
    def update_results(self, results):
        # Update results text
        self.results_text.configure(state=tk.NORMAL)
        
        # Clear previous results if this is a new batch
        if results and len(results) > 0:
            self.results_text.delete(1.0, tk.END)
        
        for result in results:
            status = result['status']
            message = result['message']
            
            # Format output based on status
            if status == 'MATCH':
                self.results_text.insert(tk.END, "✅ ")
                self.results_text.insert(tk.END, message + "\n", "match")
                self.results_text.insert(tk.END, f"    Hash: {result['hash']}\n\n")
            elif status == 'MODIFIED':
                self.results_text.insert(tk.END, "❌ ")
                self.results_text.insert(tk.END, message + "\n", "modified")
                self.results_text.insert(tk.END, f"    Stored Hash: {result['stored_hash']}\n")
                self.results_text.insert(tk.END, f"    Current Hash: {result['current_hash']}\n\n")
            elif status == 'NOT FOUND':
                self.results_text.insert(tk.END, "⚠️ ")
                self.results_text.insert(tk.END, message + "\n\n", "notfound")
            else:  # ERROR
                self.results_text.insert(tk.END, "❗ ")
                self.results_text.insert(tk.END, message + "\n\n", "error")
        
        # Configure text tags for color
        self.results_text.tag_configure("match", foreground="green")
        self.results_text.tag_configure("modified", foreground="red")
        self.results_text.tag_configure("notfound", foreground="orange")
        self.results_text.tag_configure("error", foreground="red")
        
        self.results_text.see(tk.END)
        self.results_text.configure(state=tk.NORMAL)
        
        # Hide progress and update status
        self.progress.stop()
        self.progress.pack_forget()
        
        match_count = sum(1 for r in results if r['status'] == 'MATCH')
        modified_count = sum(1 for r in results if r['status'] == 'MODIFIED')
        not_found_count = sum(1 for r in results if r['status'] == 'NOT FOUND')
        error_count = sum(1 for r in results if r['status'] == 'ERROR')
        
        self.update_status(
            f"Verification complete: {match_count} match, {modified_count} modified, "
            f"{not_found_count} not found, {error_count} errors"
        )
    
    def update_status(self, message):
        self.status_var.set(message)
    
    def calculate_sha256(self, file_path):
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

# Add Tkinter drag and drop support
# This is needed because standard Tkinter doesn't have built-in drag and drop
def make_dnd_aware():
    # First, check if TkinterDnD2 is available
    try:
        from tkinterdnd2 import TkinterDnD, DND_FILES
        return TkinterDnD.Tk
    except ImportError:
        # If not, use an alternative approach or provide instructions
        print("TkinterDnD2 not found. Install it with 'pip install tkinterdnd2' for drag and drop support.")
        print("Falling back to basic functionality.")
        
        # Create dummy methods for compatibility
        tk.Text.drop_target_register = lambda self, *args: None
        tk.Text.dnd_bind = lambda self, *args: None
        return tk.Tk

if __name__ == "__main__":
    # Use TkinterDnD if available, otherwise use regular Tk
    root_class = make_dnd_aware()
    root = root_class()
    app = HashVerifierGUI(root)
    root.mainloop()
