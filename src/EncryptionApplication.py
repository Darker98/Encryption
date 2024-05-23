# Libraries for GUI
import tkinter as tk
from tkinter import filedialog, ttk, simpledialog
from PIL import Image, ImageTk
from ttkthemes import ThemedStyle

# Libraries for encryption
from cryptography.fernet import Fernet
from secrets import token_bytes
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad, unpad

global image_file
global encryption_options

def encrypt_fernet(path):
    # Create a fernet object using generated key
    key = Fernet.generate_key()
    fernet_object = Fernet(key)

    with open(path, 'rb') as file:
        plain_text = file.read()

    # Encrypt and return
    cipher_text = fernet_object.encrypt(plain_text)
    
    # Save encrypted file
    with open(f"{path}_encrypted.txt", 'wb') as file:
        file.write(cipher_text)

    return key

def decrypt_fernet(path, key):
    # Attempt to create a fernet object using given key
    try:
        fernet_object = Fernet(key)
    except (ValueError, TypeError):
        print("Invalid key provided")
        return -1
    
    with open(path, 'rb') as file:
        cipher_text = file.read()

    # Decrypt and return
    plain_text = fernet_object.decrypt(cipher_text)

    with open(f"{path}_decrypted.txt", "wb") as file:
        file.write(plain_text)

    return key

def image_XOR(path, key = 7):
    # Open the image
    try:
        img = Image.open(path)
    except FileNotFoundError:
        print("File not found")
        return -1

    # Get the pixel data
    pixels = list(img.getdata())

    # Perform XOR encryption on each pixel
    encrypted_pixels = [tuple(p ^ key for p in pixel) for pixel in pixels]

    # Create a new image with the encrypted pixel data
    encrypted_img = Image.new(img.mode, img.size)
    encrypted_img.putdata(encrypted_pixels)

    # Save the encrypted image
    encrypted_img.save(f"{path}_encrypted.jpg")

    return key

def xor_encryption(path, key = 'L'):
    cipher_text = "" # Initialize a new string

    with open(path, 'r') as file:
        text = file.read()

    # Iterate through plain text and perform XOR operation with key
    for char in text:
        encrypted_char = ord(char) ^ ord(key)
        cipher_text += chr(encrypted_char)

    with open(f"{path}_result.txt", 'w') as file:
        file.write(cipher_text)

    return key


def encrypt_caeser(path, key = 5):
    result = ""
    
    with open(path, 'r') as file:
        text = file.read()

    for i in range(len(text)):
        char = text[i]
        
        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((ord(char) + key - 65) % 26 + 65)
    
        # Encrypt lowercase characters
        elif (char.islower()):
            result += chr((ord(char) + key - 97) % 26 + 97)

        # Non-alphabets remain the same
        else:
            result += char

    with open(f"{path}_result.txt", 'w') as file:
        file.write(result)

    return key


def generate_key():
    # Generate a random 256-bit (32-byte) key
    key = token_bytes(32)
    return key

def image_AES(path):
    try:
        img = Image.open(path)
    except:
        print("File not found")
        return -1
    
    key = generate_key()

    img_bytes = img.tobytes()

    try:
        cipher = AES.new(key, AES.MODE_ECB)
    except:
        print("Key invalid")
        return -1
    
    encrypted_bytes = cipher.encrypt(pad(img_bytes, AES.block_size))

    encrypted_img = Image.frombytes(img.mode, img.size, encrypted_bytes)
    encrypted_img.save(f"{path}_encrypted.jpg")

    return key
    
def image_AES_decrypt(path, key):
    try:
        encrypted_img = Image.open(path)
    except FileNotFoundError:
        print("File not found")
        return -1

    encrypted_bytes = encrypted_img.tobytes()

    try:
        cipher = AES.new(key, AES.MODE_ECB)
    except:
        print("Invalid key")
        return -1
    
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

    decrypted_img = Image.frombytes(encrypted_img.mode, encrypted_img.size, decrypted_bytes)
    decrypted_img.save(f"{path}_decrypted.jpg")

    return key

def image_blowfish(path):
    # Open the image
    try:
        img = Image.open(path)
    except FileNotFoundError:
        print("File not found")
        return -1

    key = generate_key()
    img_bytes = img.tobytes()

    # Create a Blowfish cipher object
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)

    # Encrypt the image bytes
    encrypted_bytes = cipher.encrypt(pad(img_bytes, Blowfish.block_size))

    # Create a new image with the encrypted bytes
    encrypted_img = Image.frombytes(img.mode, img.size, encrypted_bytes)

    # Save the encrypted image
    encrypted_img.save(f"{path}_encrypted.jpg")

    return key

def image_blowfish_decrypt(path, key):
    # Open the encrypted image
    try:
        encrypted_img = Image.open(path)
    except FileNotFoundError:
        print("File not found")
        return -1

    # Convert the image to bytes
    encrypted_bytes = encrypted_img.tobytes()

    # Create a Blowfish cipher object
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    except:
        print("Invalid key")
        return -1

    # Decrypt the image bytes
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), Blowfish.block_size)

    # Create a new image with the decrypted bytes
    decrypted_img = Image.frombytes(encrypted_img.mode, encrypted_img.size, decrypted_bytes)

    # Save the decrypted image
    decrypted_img.save(f"{path}_decrypted.jgp")

    return key

def browse_file():
    file_path = filedialog.askopenfilename()
    file_path_var.set(file_path)

    # Display image for demonstration (can be replaced with actual code for text file handling)
    global image_file, encryption_options
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        image_file = True
        image = Image.open(file_path)
        image.thumbnail((200, 200))
        photo = ImageTk.PhotoImage(image)
        image_label.config(image=photo)
        image_label.image = photo
        encryption_options = ["XOR Encryption", "AES Encryption", "Blowfish Encryption"]
 
    else:
        image_file = False
        encryption_options = ["XOR Encryption", "Caeser Cipher", "Fernet Encryption"]

    update_options()

def ask_for_key():
    key = simpledialog.askstring("Enter Key", "Enter the decryption key:")
    return key

def encrypt():
    selected_option = selected_option_var.get()
    if selected_option == "Fernet Encryption":
        key = encrypt_fernet(file_path_var.get())
    elif selected_option == "XOR Encryption":
        if image_file:
            key = image_XOR(file_path_var.get())
        else:
            key = xor_encryption(file_path_var.get())
    elif selected_option == "AES Encryption":
        key = image_AES(file_path_var.get())
    elif selected_option == "Blowfish Encryption":
        key = image_blowfish(file_path_var.get())
    else:
        key = encrypt_caeser(file_path_var.get(), 5)

    print(key)
    if key is not None:
        simpledialog.messagebox.showinfo("Encryption Successful", "File encrypted successfully. Key: {}".format(key))

def decrypt():
    selected_option = selected_option_var.get()
    key = None

    if selected_option == "Fernet Encryption":
        key = ask_for_key()
        if key:
            key = decrypt_fernet(file_path_var.get(), key)
    elif selected_option == "XOR Encryption":
        key = ask_for_key()
        if key:
            if image_file:
                key = image_XOR(file_path_var.get(), key)
            else:
                key = xor_encryption(file_path_var.get(), key)
    elif selected_option == "Caeser Cipher":
        key = ask_for_key()
        if key:
            key = encrypt_caeser(file_path_var.get(), -int(key))
    elif selected_option == "AES Encryption":
        key = ask_for_key()
        if key:
            key = image_AES_decrypt(file_path_var.get(), key)
    elif selected_option == "Blowfish Encryption":
        key = ask_for_key()
        if key:
            key = image_blowfish_decrypt(file_path_var.get(), key)

    if key == -1:
        simpledialog.messagebox.showinfo("Decryption Failed", "Key is invalid.")
    elif key is not None:
        simpledialog.messagebox.showinfo("Decryption Successful", "File decrypted successfully.")
    else:
        simpledialog.messagebox.showinfo("No key entered", "Please enter a key.")

def update_options():
    ttk.Label(option_frame, text="Select Encryption Option:", font=("Arial", 12)).grid(row=0, column=0, sticky="e", padx=5, pady=5)
    options_menu = ttk.OptionMenu(option_frame, selected_option_var, *encryption_options)
    options_menu.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Fixed Theme Colors
fixed_theme_colors = {"background": "#FFFFFF", "foreground": "#000000", "accent": "#4CAF50"}

# GUI Components
root = tk.Tk()
root.title("Cryptography Application")

# Variables
file_path_var = tk.StringVar()
selected_option_var = tk.StringVar(value="")

# Style
style = ThemedStyle(root)
style.set_theme("arc") 

# File Upload Section
file_frame = ttk.Frame(root)
file_frame.pack(pady=10, padx=20, fill="both", expand=True)

ttk.Label(file_frame, text="Select File:", font=("Arial", 12)).grid(row=0, column=0, sticky="e", padx=5, pady=5)
ttk.Entry(file_frame, textvariable=file_path_var, width=40, state="disabled", font=("Arial", 10)).grid(row=0, column=1, padx=5, pady=5)
ttk.Button(file_frame, text="Browse", command=browse_file).grid(row=0, column=2, padx=5, pady=5)

# Image Display
image_frame = ttk.Frame(root)
image_frame.pack(pady=10, padx=20, fill="both", expand=True)

image_label = ttk.Label(image_frame)
image_label.pack()

# Encryption Options
encryption_options = ["Upload a file..."]
option_frame = ttk.Frame(root)
option_frame.pack(pady=10, padx=20, fill="both", expand=True)
update_options()

# Encryption and Decryption Buttons
action_frame = ttk.Frame(root)
action_frame.pack(pady=10, padx=20, fill="both", expand=True)

ttk.Button(action_frame, text="Encrypt", command=encrypt).grid(row=0, column=0, padx=5, pady=5)
ttk.Button(action_frame, text="Decrypt", command=decrypt).grid(row=0, column=1, padx=5, pady=5)

# Configure the style for the entire window
style.configure("TFrame", background=fixed_theme_colors["background"])
style.configure("TLabel", background=fixed_theme_colors["background"], foreground=fixed_theme_colors["foreground"])
style.configure("TEntry", background=fixed_theme_colors["background"], foreground=fixed_theme_colors["foreground"])
style.configure("TButton", background=fixed_theme_colors["background"], foreground=fixed_theme_colors["foreground"])

root.mainloop()
