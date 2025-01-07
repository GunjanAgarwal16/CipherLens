
# --- Importing Required Libraries ---
import os
import time
import random
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import cv2
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

# --- GUI Setup ---
window = tk.Tk()
window.geometry("1200x800")
window.title("Autonomous Image Encryption & Decryption")
window.configure(bg="#e8eff7")

# Global variables
original_img_path = None
encryption_key = None
random_seed = None  # For deterministic random algorithm selection
encryption_info_path = "encryption_info.txt"
encrypted_data_path = "encrypted_image_data.npy"

# --- Utility Functions ---
# Padding data to match block size (for encryption)
def pad_data(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length), padding_length

# Removing padding from decrypted data
def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]

# --- AES Encryption & Decryption Functions ---

def aes_encrypt_image(img_rgb, key):
    key = hashlib.sha256(key.encode()).digest()[:16]  # AES key must be 16 bytes
    aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = aes_cipher.encryptor()
    
    flat_data = img_rgb.flatten().tobytes()  # Flatten the image to bytes
    padded_data, padding_length = pad_data(flat_data, block_size=16)  # Pad to 16-byte blocks
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    return encrypted_array, padding_length, img_rgb.shape

def aes_decrypt_image(encrypted_img_data, key, padding_length, img_shape):
    key = hashlib.sha256(key.encode()).digest()[:16]  # AES key must be 16 bytes
    aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = aes_cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_img_data.tobytes()) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)  # Remove the padding applied during encryption
    
    # Validate size of unpadded data
    expected_size = np.prod(img_shape)
    if len(unpadded_data) < expected_size:
        raise ValueError("Decrypted data size does not match the original image size.")
    
    return np.frombuffer(unpadded_data[:expected_size], dtype=np.uint8).reshape(img_shape)




# --- Blowfish Functions ---
def blowfish_encrypt_image(img_rgb, key):
    key = hashlib.sha256(key.encode()).digest()[:16]  # Blowfish key size (up to 56 bits, use first 16 bytes)
    blowfish_cipher = Cipher(Blowfish(key), modes.ECB(), backend=default_backend())
    encryptor = blowfish_cipher.encryptor()
    
    flat_data = img_rgb.flatten().tobytes()  # Flatten the image
    padded_data, padding_length = pad_data(flat_data, block_size=8)  # Ensure multiple of 8 bytes
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    return encrypted_array, padding_length, img_rgb.shape

def blowfish_decrypt_image(encrypted_img_data, key, padding_length, img_shape):
    key = hashlib.sha256(key.encode()).digest()[:16]
    blowfish_cipher = Cipher(Blowfish(key), modes.ECB(), backend=default_backend())
    decryptor = blowfish_cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_img_data.tobytes()) + decryptor.finalize()
    
    # Remove padding
    unpadded_data = unpad_data(decrypted_data)
    
    # Validate the unpadded data size
    expected_size = np.prod(img_shape)
    if len(unpadded_data) != expected_size:
        raise ValueError(f"Decrypted data size ({len(unpadded_data)}) does not match the original image size ({expected_size}).")
    
    # Reshape the unpadded data to the original image shape
    return np.frombuffer(unpadded_data, dtype=np.uint8).reshape(img_shape)






# --- Triple DES Functions ---
def triple_des_encrypt_image(img_rgb, key):
    key = hashlib.sha256(key.encode()).digest()[:24]  # Ensure the key is 24 bytes for Triple DES
    triple_des_cipher = Cipher(TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = triple_des_cipher.encryptor()
    
    flat_data = img_rgb.flatten().tobytes()  # Flatten the image to a byte array
    padded_data, padding_length = pad_data(flat_data, block_size=8)  # Triple DES requires 8-byte blocks
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    return encrypted_array, padding_length, img_rgb.shape


def triple_des_decrypt_image(encrypted_img_data, key, padding_length, img_shape):
    key = hashlib.sha256(key.encode()).digest()[:24]  # Ensure the key is 24 bytes for Triple DES
    triple_des_cipher = Cipher(TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = triple_des_cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_img_data.tobytes()) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)  # Remove the padding applied during encryption
    
    # Validate that the unpadded data matches the expected size
    expected_size = np.prod(img_shape)
    if len(unpadded_data) < expected_size:
        raise ValueError("Decrypted data size does not match the original image size.")
    
    return np.frombuffer(unpadded_data[:expected_size], dtype=np.uint8).reshape(img_shape)



# --- Save Encryption Info ---
def save_encryption_info(algorithm, padding_length, img_shape):
    with open(encryption_info_path, "w") as f:
        f.write(f"{algorithm}\n{padding_length}\n{img_shape[0]}\n{img_shape[1]}\n{img_shape[2]}")

def load_encryption_info():
    with open(encryption_info_path, "r") as f:
        data = f.readlines()
    algorithm = data[0].strip()
    padding_length = int(data[1].strip())
    img_shape = tuple(map(int, data[2:5]))
    return algorithm, padding_length, img_shape

def generate_and_store_random_seed(seed_file="random_seed.txt"):
    random_seed = random.SystemRandom().randint(0, 99999999)  # Securely generate a random seed
    with open(seed_file, "w") as f:
        f.write(str(random_seed))  # Save the random seed to a file
    return random_seed

def load_random_seed(seed_file="random_seed.txt"):
    if not os.path.exists(seed_file):
        raise ValueError("Random seed file not found!")
    with open(seed_file, "r") as f:
        return int(f.read().strip())


# --- Encrypt Image (Modified) ---
def encrypt_image():
    global encryption_key, random_seed

    img_rgb = cv2.imread(original_img_path, cv2.IMREAD_COLOR)
    if img_rgb is None:
        messagebox.showerror("Error", "Unable to read the image.")
        return

    encryption_key = simpledialog.askstring("Encryption Key", "Enter an encryption key:")
    if not encryption_key:
        messagebox.showwarning("Warning", "Encryption key is required!")
        return

    random_seed = generate_and_store_random_seed()  # Automatically generate and store the random seed
    random.seed(random_seed)

    algorithm = random.choice(["AES",  "Blowfish", "Triple DES"])
    
    start_time = time.time()
    if algorithm == "AES":
        encrypted_data, padding_length, img_shape = aes_encrypt_image(img_rgb, encryption_key)
    
    elif algorithm == "Blowfish":
        encrypted_data, padding_length, img_shape = blowfish_encrypt_image(img_rgb, encryption_key)
    elif algorithm == "Triple DES":
        encrypted_data, padding_length, img_shape = triple_des_encrypt_image(img_rgb, encryption_key)

    # Save encryption details and data
    save_encryption_info(algorithm, padding_length, img_shape)
    if algorithm in ["AES", "Blowfish", "Triple DES"]:
        np.save(encrypted_data_path, encrypted_data)

    end_time = time.time()
    encryption_time = end_time - start_time

    # For display, create a mock visualization of the encrypted image
    if algorithm in ["AES", "Blowfish", "Triple DES"]:
        encrypted_img = encrypted_data[:np.prod(img_shape)].reshape(img_shape)  # Visual mock (not actual encrypted content)
        encrypted_img_path = "temp_encrypted_image_display.jpg"
        cv2.imwrite(encrypted_img_path, encrypted_img)
        display_image(encrypted_img_path, panelB)

    status_message.set(f"Encryption Successful \n"
                       f"Time Taken: {encryption_time:.2f} seconds.")


# --- Decrypt Image (Modified) ---
def decrypt_image():
    global encryption_key

    if not os.path.exists(encryption_info_path):
        messagebox.showwarning("Warning", "No encryption info found.")
        return

    decryption_key = simpledialog.askstring("Decryption Key", "Enter the decryption key:")
    if not decryption_key:
        messagebox.showwarning("Warning", "Decryption key is required!")
        return

    try:
        random_seed = load_random_seed()  # Load the previously generated random seed
    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return

    random.seed(random_seed)
    algorithm, padding_length, img_shape = load_encryption_info()

    try:
        start_time = time.time()
        encrypted_data = np.load(encrypted_data_path)  # Load the encrypted image data

        if algorithm == "AES":
            decrypted_img = aes_decrypt_image(encrypted_data, decryption_key, padding_length, img_shape)
        elif algorithm == "Blowfish":
            decrypted_img = blowfish_decrypt_image(encrypted_data, decryption_key, padding_length, img_shape)
        elif algorithm == "Triple DES":
            decrypted_img = triple_des_decrypt_image(encrypted_data, decryption_key, padding_length, img_shape)
        else:
            messagebox.showerror("Error", "Unsupported encryption algorithm.")
            return

        # Verify if the decrypted image is valid by checking its shape and content
        if decrypted_img.shape != img_shape:
            raise ValueError("Decrypted data does not match the expected image shape.")

        end_time = time.time()
        decryption_time = end_time - start_time

        # Save and display the decrypted image
        decrypted_img_path = "decrypted_image.jpg"
        cv2.imwrite(decrypted_img_path, decrypted_img)
        display_image(decrypted_img_path, panelB)

        status_message.set(f"Decryption Successful \n"
                           f"Time Taken: {decryption_time:.2f} seconds.")

    except Exception as e:
        # Catch any exception during decryption, typically due to a wrong key
        messagebox.showerror("Decryption Error", "Decryption failed. Please check your key and try again.")
        status_message.set("Decryption Failed.")



# --- Open Image ---
def open_image():
    global original_img_path

    original_img_path = filedialog.askopenfilename(
        title="Select an Image", filetypes=[("Image Files", "*.jpg *.png *.bmp *.jpeg")]
    )
    if not original_img_path:
        return

    display_image(original_img_path, panelA)
    status_message.set("Image Loaded")

# --- Clear Screen ---
def clear_screen():
    global original_img_path, encryption_key

    original_img_path = None
    encryption_key = None

    panelA.configure(image=None)
    panelA.image = None
    panelB.configure(image=None)
    panelB.image = None

    status_message.set("Screen cleared. Load a new image to start.")

    for file in ["encrypted_image_data.npy", "temp_encrypted_image_display.jpg", "decrypted_image.jpg",
                 "encryption_info.txt"]:
        if os.path.exists(file):
            os.remove(file)

# --- Display Image ---
def display_image(image_path, panel):
    img = Image.open(image_path).convert("RGB").resize((400, 400), Image.LANCZOS)
    img_tk = ImageTk.PhotoImage(img)
    panel.configure(image=img_tk)
    panel.image = img_tk

# --- GUI Layout ---
header = tk.Frame(window, bg="#34495e", height=80)
header.pack(fill="x")
header_label = tk.Label(header, text="Autonomous Image Encryption & Decryption", font=("Helvetica", 24, "bold"), fg="white", bg="#34495e")
header_label.pack(pady=20)

sidebar = tk.Frame(window, bg="#2c3e50", width=200)
sidebar.pack(fill="y", side="left")

buttons = [
    ("Open Image", open_image),
    ("Encrypt", encrypt_image),
    ("Decrypt", decrypt_image),
    ("Clear Screen", clear_screen),
    ("Exit", window.quit)
]
for text, command in buttons:
    button = tk.Button(sidebar, text=text, command=command, font=("Arial", 12), bg="#1abc9c", fg="white")
    button.pack(fill="x", pady=10, padx=20)

status_frame = tk.Frame(window, bg="#e8eff7", height=100)
status_frame.pack(side="bottom", fill="x")
status_message = tk.StringVar(value="Welcome! Please load an image to start.")
status_label = tk.Label(status_frame, textvariable=status_message, font=("Arial", 12), bg="#e8eff7", fg="black")
status_label.pack(pady=10)

content_frame = tk.Frame(window, bg="#e8eff7")
content_frame.pack(fill="both", expand=True, padx=20, pady=20)

frameA = tk.Frame(content_frame, bg="white", bd=2, relief="groove")
frameA.pack(side="left", padx=20, pady=20, expand=True)

frameB = tk.Frame(content_frame, bg="white", bd=2, relief="groove")
frameB.pack(side="right", padx=20, pady=20, expand=True)

panelA = tk.Label(frameA)
panelA.pack()

panelB = tk.Label(frameB)
panelB.pack()

tk.Label(frameA, text="Original Image", font=("Arial", 16), bg="white").pack(side="bottom", pady=10)
tk.Label(frameB, text="Encrypted/Decrypted Image", font=("Arial", 16), bg="white").pack(side="bottom", pady=10)

window.mainloop()
