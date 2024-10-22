import tkinter as tk
from tkinter import scrolledtext, messagebox

# Примерные S-блоки ГОСТ 28147-89
S_BOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 14, 3, 11, 6, 8, 12],
]

def substitute(value: int) -> int:
    result = 0
    for i in range(8):
        s_block = S_BOX[i][(value >> (4 * i)) & 0xF]
        result |= s_block << (4 * i)
    return result

def rol(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

def gost_round(left: int, right: int, key: int) -> (int, int):
    temp = (left + key) % (2 ** 32)
    temp = substitute(temp)
    temp = rol(temp, 11)
    new_right = right ^ temp
    return new_right, left

def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def gost_encrypt_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(24):
        right, left = gost_round(left, right, key_parts[i % 8])
    for i in range(8):
        right, left = gost_round(left, right, key_parts[7 - i])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')

def gost_decrypt_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(8):
        right, left = gost_round(left, right, key_parts[i])
    for i in range(24):
        right, left = gost_round(left, right, key_parts[7 - (i % 8)])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')

def gost_encrypt_message(message: bytes, key: bytes) -> bytes:
    message = pad(message)
    encrypted_message = b''
    for i in range(0, len(message), 8):
        block = message[i:i+8]
        encrypted_message += gost_encrypt_block(block, key)
    return encrypted_message

def gost_decrypt_message(encrypted_message: bytes, key: bytes) -> bytes:
    decrypted_message = b''
    for i in range(0, len(encrypted_message), 8):
        block = encrypted_message[i:i+8]
        decrypted_message += gost_decrypt_block(block, key)
    return unpad(decrypted_message)

# Функции для работы с UI
def encrypt_message():
    try:
        message = message_entry.get("1.0", tk.END).strip().encode()
        key = key_entry.get().encode()
        if len(key) != 32:
            messagebox.showerror("Ошибка", "Ключ должен быть длиной 32 байта!")
            return
        encrypted = gost_encrypt_message(message, key)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, encrypted.hex())
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

def decrypt_message():
    try:
        encrypted_message = bytes.fromhex(message_entry.get("1.0", tk.END).strip())
        key = key_entry.get().encode()
        if len(key) != 32:
            messagebox.showerror("Ошибка", "Ключ должен быть длиной 32 байта!")
            return
        decrypted = gost_decrypt_message(encrypted_message, key)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, decrypted.decode())
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

# Настройка UI
window = tk.Tk()
window.title("Шифрование ГОСТ 28147-89")

# Поля ввода
tk.Label(window, text="Сообщение:").grid(row=0, column=0, sticky="w")
message_entry = scrolledtext.ScrolledText(window, width=40, height=5)
message_entry.grid(row=1, column=0)

tk.Label(window, text="Ключ (32 байта):").grid(row=2, column=0, sticky="w")
key_entry = tk.Entry(window, width=40)
key_entry.grid(row=3, column=0)

# Кнопки шифрования и дешифрования
encrypt_button = tk.Button(window, text="Зашифровать", command=encrypt_message)
encrypt_button.grid(row=4, column=0)

decrypt_button = tk.Button(window, text="Расшифровать", command=decrypt_message)
decrypt_button.grid(row=5, column=0)

# Поле для результата
tk.Label(window, text="Результат:").grid(row=6, column=0, sticky="w")
result_text = scrolledtext.ScrolledText(window, width=40, height=5)
result_text.grid(row=7, column=0)

# Запуск основного цикла
window.mainloop()
