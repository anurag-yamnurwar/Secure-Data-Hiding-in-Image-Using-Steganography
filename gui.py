import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import encryption
import decryption

cover_image_path = ""
encrypted_image_path = ""

def load_image(var_name, label):
    global cover_image_path, encrypted_image_path
    path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp *.png")])
    if path:
        if var_name == "cover":
            cover_image_path = path
        else:
            encrypted_image_path = path
        label.config(text=path)
    else:
        label.config(text="No file selected")

def encrypt_message():
    if not cover_image_path:
        messagebox.showerror("Error", "Please load a cover image!")
        return
    if not enc_message_entry.get() or not enc_password_entry.get():
        messagebox.showerror("Error", "Please enter both message and passcode!")
        return
    encryption.encrypt(cover_image_path, enc_message_entry.get(), enc_password_entry.get())
    messagebox.showinfo("Success", "Message encrypted and saved.")

def decrypt_message():
    if not encrypted_image_path:
        messagebox.showerror("Error", "Please load an encrypted image!")
        return
    if not dec_password_entry.get() or not dec_length_entry.get().isdigit():
        messagebox.showerror("Error", "Enter valid passcode and message length!")
        return
    message = decryption.decrypt(encrypted_image_path, dec_password_entry.get(), int(dec_length_entry.get()))
    dec_text.delete(1.0, tk.END)
    dec_text.insert(tk.END, message if message else "Decryption failed!")

root = tk.Tk()
root.title("Image Steganography")

# GUI Elements
def create_section(title, parent, elements):
    frame = tk.LabelFrame(parent, text=title)
    frame.pack(padx=10, pady=5, fill="x")
    for elem in elements:
        elem.pack(pady=2)
    return frame

encryption_frame = create_section("Encryption", root, [
    tk.Button(root, text="Load Cover Image", command=lambda: load_image("cover", cover_label)),
    (cover_label := tk.Label(root, text="No file selected")),
    tk.Label(root, text="Secret Message:"),
    (enc_message_entry := tk.Entry(root, width=50)),
    tk.Label(root, text="Passcode:"),
    (enc_password_entry := tk.Entry(root, width=50, show="*")),
    tk.Button(root, text="Encrypt", command=encrypt_message)
])

decryption_frame = create_section("Decryption", root, [
    tk.Button(root, text="Load Encrypted Image", command=lambda: load_image("encrypted", encrypted_label)),
    (encrypted_label := tk.Label(root, text="No file selected")),
    tk.Label(root, text="Passcode:"),
    (dec_password_entry := tk.Entry(root, width=50, show="*")),
    tk.Label(root, text="Message Length:"),
    (dec_length_entry := tk.Entry(root, width=50)),
    tk.Button(root, text="Decrypt", command=decrypt_message),
    (dec_text := scrolledtext.ScrolledText(root, width=50, height=5))
])

root.mainloop()
