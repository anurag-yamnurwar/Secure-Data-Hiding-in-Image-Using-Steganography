import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import encryption
import decryption

# Global Variables
cover_image_path = ""
encrypted_image_path = ""

# GUI Functions
def load_cover_image():
    global cover_image_path
    cover_image_path = filedialog.askopenfilename(title="Select Cover Image", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp")])
    cover_label.config(text=cover_image_path if cover_image_path else "No file selected")

def load_encrypted_image():
    global encrypted_image_path
    encrypted_image_path = filedialog.askopenfilename(title="Select Encrypted Image", filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")])
    encrypted_label.config(text=encrypted_image_path if encrypted_image_path else "No file selected")

def encrypt_message():
    if not cover_image_path:
        messagebox.showerror("Error", "Please load a cover image!")
        return
    msg = enc_message_entry.get()
    password = enc_password_entry.get()
    if not msg or not password:
        messagebox.showerror("Error", "Please enter both message and passcode!")
        return
    encryption.encrypt(cover_image_path, msg, password)
    messagebox.showinfo("Success", "Message encrypted and saved.")

def decrypt_message():
    if not encrypted_image_path:
        messagebox.showerror("Error", "Please load an encrypted image!")
        return
    password_input = dec_password_entry.get()
    length = dec_length_entry.get()
    if not length.isdigit():
        messagebox.showerror("Error", "Invalid message length!")
        return
    message = decryption.decrypt(encrypted_image_path, password_input, int(length))
    if message:
        dec_text.delete(1.0, tk.END)
        dec_text.insert(tk.END, message)
    else:
        messagebox.showerror("Error", "Decryption failed!")

# GUI Setup
root = tk.Tk()
root.title("Image Steganography")

# Encryption Section
encryption_frame = tk.LabelFrame(root, text="Encryption")
encryption_frame.pack(padx=10, pady=10, fill="x")
btn_load_cover = tk.Button(encryption_frame, text="Load Cover Image", command=load_cover_image)
btn_load_cover.pack()
cover_label = tk.Label(encryption_frame, text="No file selected")
cover_label.pack()
tk.Label(encryption_frame, text="Secret Message:").pack()
enc_message_entry = tk.Entry(encryption_frame, width=50)
enc_message_entry.pack()
tk.Label(encryption_frame, text="Passcode:").pack()
enc_password_entry = tk.Entry(encryption_frame, width=50, show="*")
enc_password_entry.pack()
btn_encrypt = tk.Button(encryption_frame, text="Encrypt", command=encrypt_message)
btn_encrypt.pack()

# Decryption Section
decryption_frame = tk.LabelFrame(root, text="Decryption")
decryption_frame.pack(padx=10, pady=10, fill="x")
btn_load_encrypted = tk.Button(decryption_frame, text="Load Encrypted Image", command=load_encrypted_image)
btn_load_encrypted.pack()
encrypted_label = tk.Label(decryption_frame, text="No file selected")
encrypted_label.pack()
tk.Label(decryption_frame, text="Passcode:").pack()
dec_password_entry = tk.Entry(decryption_frame, width=50, show="*")
dec_password_entry.pack()
tk.Label(decryption_frame, text="Message Length:").pack()
dec_length_entry = tk.Entry(decryption_frame, width=50)
dec_length_entry.pack()
btn_decrypt = tk.Button(decryption_frame, text="Decrypt", command=decrypt_message)
btn_decrypt.pack()
dec_text = scrolledtext.ScrolledText(decryption_frame, width=50, height=5)
dec_text.pack()

root.mainloop()

### Encryption File (encryption.py)
import cv2

def encrypt(image_path, message, password):
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError("Cover image not found!")
    with open("pass.txt", "w") as f:
        f.write(password)
    n, m, z = 0, 0, 0
    for char in message:
        if n >= img.shape[0] or m >= img.shape[1]:
            raise ValueError("Message too long for image!")
        img[n, m, z] = ord(char)
        n, m, z = n + 1, m + 1, (z + 1) % 3
    cv2.imwrite("encryptedImage.png", img)

### Decryption File (decryption.py)
import cv2

def decrypt(image_path, password, length):
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError("Encrypted image not found!")
    try:
        with open("pass.txt", "r") as f:
            correct_pass = f.read().strip()
    except:
        raise FileNotFoundError("Password file not found!")
    if password != correct_pass:
        return None
    message, n, m, z = "", 0, 0, 0
    for _ in range(length):
        if n >= img.shape[0] or m >= img.shape[1]:
            break
        message += chr(img[n, m, z])
        n, m, z = n + 1, m + 1, (z + 1) % 3
    return message

### Main File (main.py)
import gui

def main():
    gui.root.mainloop()

if __name__ == "__main__":
    main()
