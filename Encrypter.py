from cryptography.fernet import Fernet, InvalidToken
import tkinter as tk, sv_ttk, hashlib, base64, pickle, os, datetime, tempfile
from tkinter import ttk

root = tk.Tk()
root.geometry("800x265")

icon = tk.PhotoImage(file="assets/icon.png")
root.title("NSE")
root.iconphoto(False, icon)

def encrypt():
    try:
        input_text = input_field.get()
        key = key_field.get()

        md5_hash = hashlib.md5(key.encode()).hexdigest()
        md5_bytes = bytes.fromhex(md5_hash)
        padded_key = (md5_bytes * 2)[:32]
        fernet_key = base64.urlsafe_b64encode(padded_key)

        f = Fernet(fernet_key)
        encrypted = f.encrypt(input_text.encode()).decode()

        output_field.config(text="Input encrypted successfully, saved to pickle file", font=("Arial", 12))

        aes_fold = os.path.join(tempfile.gettempdir(), "AES")
        
        os.makedirs(aes_fold, exist_ok=True)

        creation_date = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        output_path = os.path.join(aes_fold, f"NSE_{creation_date}.pkl")

        with open(output_path, "wb") as file:
            pickle.dump(encrypted, file)
            pickle.dump(key, file)
            pickle.dump(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), file)
    
    except InvalidToken:
        output_field.config(text="Error encrypting the message", font=("Arial", 12))
    except Exception as e:
        output_field.config(text=f"An error occurred: {e}", font=("Arial", 12))

def output():
    output_window = tk.Toplevel(root)
    output_window.geometry("1250x500")
    output_window.title("Output")
    output_window.iconphoto(False, icon)

    output = tk.Text(output_window, height=30, width=120)
    output.pack(fill="both", expand=True)

    aes_fold = os.path.join(tempfile.gettempdir(), "AES")
    
    for file in os.listdir(aes_fold):
        if file.startswith("NSE"):
            file_path = os.path.join(aes_fold, file)
            print(f"Processing file: {file_path}")
            try:
                with open(file_path, "rb") as f:
                    if os.stat(file_path).st_size > 0:
                        encrypted_data = pickle.load(f)
                        key_data = pickle.load(f)
                        date_data = pickle.load(f)
                        output.insert("end", f"Encrypted message: {encrypted_data}\nKey: {key_data}\nDate: {date_data}\n\n")
                        output.insert("end", "-" * 100 + "\n")
                    else:
                        print(f"File {file_path} is empty.")
            except EOFError:
                print(f"File {file_path} is corrupted or empty.")
            except pickle.UnpicklingError:
                print(f"Error unpickling file {file_path}.")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

input_txt = ttk.Label(root, text="Message")
key_txt = ttk.Label(root, text="Key name")

input_field = ttk.Entry(root, width=45)
key_field = ttk.Entry(root, width=45)

output_label = ttk.Label(root, text="Status")
output_field = ttk.Label(root, text="", width=80, wraplength=600)

button1 = ttk.Button(root, text="Encrypt", command=encrypt, width=45)
button2 = ttk.Button(root, text="Output", command=output, width=45)

input_txt.config(font=("Arial Bold", 12))
key_txt.config(font=("Arial Bold", 12))
output_label.config(font=("Arial Bold", 12))

input_txt.pack(anchor="w", pady=10, padx=10)
input_field.pack(anchor="w")

key_txt.pack(anchor="w", pady=10, padx=10)
key_field.pack(anchor="w")

output_label.pack(anchor="w", pady=10, padx=10)
output_field.pack(anchor="w", pady=10, padx=10)

button1.pack(side=tk.LEFT, pady=10, padx=10)
button2.pack(side=tk.LEFT, pady=10, padx=10)

sv_ttk.set_theme("dark")

root.mainloop()
