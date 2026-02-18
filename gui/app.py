import customtkinter as ctk
from tkinter import filedialog, messagebox
import base64
import os
from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.file_crypto import FileCrypto


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sentinel Crypt - Professional Encryption Suite")
        self.geometry("900x600")

        
        self.crypto = CryptoEngine()
        self.key_manager = KeyManager()
        self.file_crypto = FileCrypto()
        self.selected_file = None

        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_text_frame()
        self.create_file_frame()
        self.create_key_frame()

        self.show_frame("text")

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="SENTINEL\nCRYPT", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_text = ctk.CTkButton(self.sidebar, text="Text Encryption", command=lambda: self.show_frame("text"))
        self.btn_text.grid(row=1, column=0, padx=20, pady=10)

        self.btn_file = ctk.CTkButton(self.sidebar, text="File Encryption", command=lambda: self.show_frame("file"))
        self.btn_file.grid(row=2, column=0, padx=20, pady=10)

        self.btn_keys = ctk.CTkButton(self.sidebar, text="Key Manager", command=lambda: self.show_frame("keys"))
        self.btn_keys.grid(row=3, column=0, padx=20, pady=10)

    def create_text_frame(self):
        self.text_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        
        self.input_label = ctk.CTkLabel(self.text_frame, text="Input Text / Ciphertext:")
        self.input_label.pack(pady=5, anchor="w", padx=20)
        
        self.text_input = ctk.CTkTextbox(self.text_frame, height=150)
        self.text_input.pack(fill="x", padx=20, pady=5)

        
        self.key_label = ctk.CTkLabel(self.text_frame, text="Encryption Password:")
        self.key_label.pack(pady=5, anchor="w", padx=20)
        self.password_entry = ctk.CTkEntry(self.text_frame, show="*")
        self.password_entry.pack(fill="x", padx=20, pady=5)

        
        self.btn_box = ctk.CTkFrame(self.text_frame, fg_color="transparent")
        self.btn_box.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(self.btn_box, text="Encrypt", command=self.encrypt_text_action).pack(side="left", padx=5)
        ctk.CTkButton(self.btn_box, text="Decrypt", command=self.decrypt_text_action).pack(side="left", padx=5)

        
        self.output_label = ctk.CTkLabel(self.text_frame, text="Result:")
        self.output_label.pack(pady=5, anchor="w", padx=20)
        
        self.text_output = ctk.CTkTextbox(self.text_frame, height=150)
        self.text_output.pack(fill="x", padx=20, pady=5)

    def create_file_frame(self):
        self.file_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        self.file_lbl = ctk.CTkLabel(self.file_frame, text="Select a file to process", font=ctk.CTkFont(size=16))
        self.file_lbl.pack(pady=20)

        ctk.CTkButton(self.file_frame, text="Choose File", command=self.select_file).pack(pady=10)
        
        self.selected_file_label = ctk.CTkLabel(self.file_frame, text="No file selected", text_color="gray")
        self.selected_file_label.pack(pady=5)

        self.file_pass_entry = ctk.CTkEntry(self.file_frame, placeholder_text="Enter Password", show="*")
        self.file_pass_entry.pack(pady=10, fill="x", padx=40)

        ctk.CTkButton(self.file_frame, text="Encrypt File", command=self.encrypt_file_action, fg_color="green").pack(pady=5)
        ctk.CTkButton(self.file_frame, text="Decrypt File", command=self.decrypt_file_action, fg_color="orange").pack(pady=5)

    def create_key_frame(self):
        self.key_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        ctk.CTkLabel(self.key_frame, text="RSA Key Generator", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)

        self.key_name_entry = ctk.CTkEntry(self.key_frame, placeholder_text="Key Name (e.g., alice)")
        self.key_name_entry.pack(pady=10)

        self.key_pass_entry = ctk.CTkEntry(self.key_frame, placeholder_text="Key Password", show="*")
        self.key_pass_entry.pack(pady=10)

        ctk.CTkButton(self.key_frame, text="Generate Key Pair", command=self.generate_keys_action).pack(pady=20)

    def show_frame(self, name):
        self.text_frame.grid_forget()
        self.file_frame.grid_forget()
        self.key_frame.grid_forget()

        if name == "text":
            self.text_frame.grid(row=0, column=1, sticky="nsew")
        elif name == "file":
            self.file_frame.grid(row=0, column=1, sticky="nsew")
        elif name == "keys":
            self.key_frame.grid(row=0, column=1, sticky="nsew")

    

    def encrypt_text_action(self):
        pwd = self.password_entry.get()
        data = self.text_input.get("1.0", "end-1c")
        if not pwd or not data:
            messagebox.showerror("Error", "Password and Text are required.")
            return
        
        
        
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000, backend=self.crypto.backend)
            key = kdf.derive(pwd.encode())
            
            res = self.crypto.aes_encrypt(data.encode(), key)
            
            
            packed = salt + res['iv'] + res['tag'] + res['ciphertext']
            b64_out = base64.b64encode(packed).decode()
            
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", b64_out)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text_action(self):
        pwd = self.password_entry.get()
        b64_data = self.text_input.get("1.0", "end-1c")
        if not pwd or not b64_data:
            return

        try:
            packed = base64.b64decode(b64_data)
            salt = packed[:16]
            iv = packed[16:28]
            tag = packed[28:44]
            ciphertext = packed[44:]

            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000, backend=self.crypto.backend)
            key = kdf.derive(pwd.encode())

            decrypted = self.crypto.aes_decrypt(ciphertext, key, iv, tag)
            
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", decrypted.decode())
        except Exception:
            messagebox.showerror("Error", "Decryption failed. Check password or data integrity.")

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.selected_file_label.configure(text=os.path.basename(self.selected_file))

    def encrypt_file_action(self):
        if not self.selected_file or not self.file_pass_entry.get():
            messagebox.showwarning("Warning", "Select file and enter password")
            return
        try:
            out = self.file_crypto.encrypt_file(self.selected_file, self.file_pass_entry.get())
            messagebox.showinfo("Success", f"Encrypted: {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file_action(self):
        if not self.selected_file or not self.file_pass_entry.get():
            return
        try:
            out = self.file_crypto.decrypt_file(self.selected_file, self.file_pass_entry.get())
            messagebox.showinfo("Success", f"Decrypted: {out}")
        except Exception:
            messagebox.showerror("Error", "Decryption failed.")

    def generate_keys_action(self):
        name = self.key_name_entry.get()
        pwd = self.key_pass_entry.get()
        if not name or not pwd:
            return
        try:
            self.key_manager.generate_key_pair(name, pwd)
            messagebox.showinfo("Success", f"Keys generated in /keys folder for {name}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = SentinelApp()
    app.mainloop()