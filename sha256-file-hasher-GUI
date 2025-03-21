import hashlib
import os
import sys
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from datetime import datetime
import threading

class FileHasherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-256 File Hasher")
        self.root.geometry("600x500")
        self.root.minsize(500, 400)
        
        # Set up the main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output file selection
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(output_frame, text="Output File:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.output_file = tk.StringVar(value="hash_log.txt")
        output_entry = ttk.Entry(output_frame, textvariable=self.output_file, width=40)
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_button = ttk.Button(output_frame, text="Browse", command=self.browse_output_file)
        browse_button.pack(side=tk.RIGHT)
        
        # Drop zone
        drop_frame = ttk.LabelFrame(main_frame, text="Drop Files Here")
        drop_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.drop_area = tk.Text(drop_frame, height=5, background="#f0f0f0", font=("TkDefaultFont", 10))
        self.drop_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.drop_area.insert(tk.END, "Drag and drop files here to calculate SHA-256 hash")
        self.drop_area.configure(state="disabled")
        
        # Make the drop area accept dropped files
        self.drop_area.drop_target_register("DND_Files")
        self.drop_area.dnd_bind("<<Drop>>", self.drop_files)
        
        # Browse button alternative
        browse_files_button = ttk.Button(main_frame, text="Or Select Files", command=self.browse_files)
        browse_files_button.pack(pady=(0, 10))
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=10)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initialize progress bar (hidden initially)
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        
    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")],
            initialfile=self.output_file.get()
        )
        if file_path:
            self.output_file.set(file_path)
    
    def browse_files(self):
        file_paths = filedialog.askopenfilenames(
            title="Select Files to Hash",
            filetypes=[("All files", "*.*")]
        )
        if file_paths:
            self.process_files(file_paths)
    
    def drop_files(self, event):
        file_paths = event.data
        # Convert from Tkinter's format to list of paths
        if isinstance(file_paths, str):
            file_paths = self.root.splitlist(file_paths)
        self.process_files(file_paths)
    
    def process_files(self, file_paths):
        # Show progress bar
        self.progress.pack(fill=tk.X, pady=(0, 10))
        self.progress.start(10)
        self.status_var.set(f"Processing {len(file_paths)} file(s)...")
        
        # Process files in a separate thread to keep GUI responsive
        thread = threading.Thread(target=self.calculate_hashes, args=(file_paths,))
        thread.daemon = True
        thread.start()
    
    def calculate_hashes(self, file_paths):
        results = []
        
        for file_path in file_paths:
            try:
                # Calculate the hash
                hash_result = self.calculate_sha256(file_path)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"{timestamp} | {os.path.basename(file_path)} | {hash_result}"
                
                # Save to output file
                with open(self.output_file.get(), "a") as f:
                    f.write(log_entry + "\n")
                
                # Add to results
                results.append(f"{os.path.basename(file_path)}: {hash_result}")
            except Exception as e:
                results.append(f"Error processing {os.path.basename(file_path)}: {str(e)}")
        
        # Update UI on the main thread
        self.root.after(0, self.update_results, results)
    
    def update_results(self, results):
        # Update results text
        self.results_text.configure(state=tk.NORMAL)
        for result in results:
            self.results_text.insert(tk.END, result + "\n\n")
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.see(tk.END)
        
        # Hide progress and update status
        self.progress.stop()
        self.progress.pack_forget()
        self.status_var.set(f"Finished processing {len(results)} file(s). Results saved to {self.output_file.get()}")
    
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
        
        # Create a dummy drop_target_register method for compatibility
        tk.Text.drop_target_register = lambda self, *args: None
        tk.Text.dnd_bind = lambda self, *args: None
        return tk.Tk

if __name__ == "__main__":
    # Use TkinterDnD if available, otherwise use regular Tk
    root_class = make_dnd_aware()
    root = root_class()
    app = FileHasherGUI(root)
    root.mainloop()
