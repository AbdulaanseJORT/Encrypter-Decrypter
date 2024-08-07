from cryptography.fernet import Fernet, InvalidToken
import tkinter as tk, sv_ttk, hashlib, base64, pickle, os, datetime, tempfile
from tkinter import ttk

root = tk.Tk()
root.geometry("800x285")

root.title("NSD")
root.iconphoto(False, icon)

def decrypt():
    try:
        input_text = input_field.get()
        key = key_field.get()

        md5_hash = hashlib.md5(key.encode()).hexdigest()
        md5_bytes = bytes.fromhex(md5_hash)
        padded_key = (md5_bytes * 2)[:32]
        fernet_key = base64.urlsafe_b64encode(padded_key)

        f = Fernet(fernet_key)
        decrypted = f.decrypt(input_text.encode()).decode()

        output_field.config(text=f"Decrypted message: {decrypted} \nsaved to pkl for later use", font=("Arial", 12))

        aes_fold = os.path.join(tempfile.gettempdir(), "AES")
        
        os.makedirs(aes_fold, exist_ok=True)

        creation_date = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        output_path = os.path.join(aes_fold, f"NSD_{creation_date}.pkl")

        with open(output_path, "wb") as file:
            pickle.dump(decrypted, file)
            pickle.dump(key, file)
            pickle.dump(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), file)
        
        print(f"Decrypted message saved to {output_path}")

        if os.path.exists(output_path):
            print("File exists")
        else:
            print("File does not exist")
        
        with open(output_path, "rb") as file:
            decrypted_data = pickle.load(file)
            key_data = pickle.load(file)
            date_data = pickle.load(file)
            print(decrypted_data)
            print(key_data)
            print(date_data)

    except InvalidToken:
        output_field.config(text="Error decrypting the message", font=("Arial", 12))
    except Exception as e:
        output_field.config(text=f"An error occurred: {e}", font=("Arial", 12))

def history():
    history_window = tk.Toplevel(root)
    history_window.geometry("1000x500")
    history_window.title("History")
    history_window.iconphoto(False, icon)

    history_display = tk.Text(history_window, height=30, width=120)
    history_display.pack()


    aes_fold = os.path.join(tempfile.gettempdir(), "AES")
    
    for file in os.listdir(aes_fold):
        if file.startswith("NSD"):
            path = os.path.join(aes_fold, file)
            with open(path, "rb") as file:
                decrypted_data = pickle.load(file)
                key_data = pickle.load(file)
                date_data = pickle.load(file)

                history_display.insert(tk.END, f"Decrypted message: {decrypted_data} \nKey: {key_data} \nDate: {date_data}\n\n")
                history_display.insert(tk.END, "-----------------------------------\n\n")
# ui elements

input_txt = ttk.Label(root, text="Message")
key_txt = ttk.Label(root, text="Key")

input_field = ttk.Entry(root, width=45)
key_field = ttk.Entry(root, width=45)

output_label = ttk.Label(root, text="Status")
output_field = ttk.Label(root, text="", width=80, wraplength=600)

button1 = ttk.Button(root, text="Decrypt", command=decrypt, width=45)

button2 = ttk.Button(root, text="History", command=history, width=45)
# Style configurations
input_txt.config(font=("Arial Bold", 12))
key_txt.config(font=("Arial Bold", 12))
output_label.config(font=("Arial Bold", 12))

# Packing UI elements
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
