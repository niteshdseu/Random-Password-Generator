import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(rn_pass, root):
        rn_pass.root = root
        rn_pass.root.title("Password Generator")
        rn_pass.root.geometry("400x350")

       # self.label = tk.Label(root, text="Password Generator", bg='green', font=("Helvetica", 16, "bold"))
        #self.label.place(x=100, y=20, height=60, width=400)

        rn_pass.length_label = ttk.Label(root, text="Password Length:")
        rn_pass.length_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        rn_pass.length_entry = ttk.Entry(root, width=10)
        rn_pass.length_entry.grid(row=0, column=1, padx=10, pady=10)

        rn_pass.complexity_label = ttk.Label(root, text="Password Complexity:")
        rn_pass.complexity_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        rn_pass.complexity_var = tk.StringVar()
        rn_pass.complexity_low_radio = ttk.Radiobutton(root, text="Low", variable=rn_pass.complexity_var, value="low")
        rn_pass.complexity_low_radio.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        rn_pass.complexity_medium_radio = ttk.Radiobutton(root, text="Medium", variable=rn_pass.complexity_var, value="medium")
        rn_pass.complexity_medium_radio.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        rn_pass.complexity_high_radio = ttk.Radiobutton(root, text="High", variable=rn_pass.complexity_var, value="high")
        rn_pass.complexity_high_radio.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        rn_pass.include_chars_label = ttk.Label(root, text="Include Characters:")
        rn_pass.include_chars_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        rn_pass.include_chars_frame = ttk.Frame(root)
        rn_pass.include_chars_frame.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        rn_pass.use_letters_var = tk.BooleanVar()
        rn_pass.use_letters_check = ttk.Checkbutton(rn_pass.include_chars_frame, text="Letters", variable=rn_pass.use_letters_var)
        rn_pass.use_letters_check.pack(side="left")

        rn_pass.use_numbers_var = tk.BooleanVar()
        rn_pass.use_numbers_check = ttk.Checkbutton(rn_pass.include_chars_frame, text="Numbers", variable=rn_pass.use_numbers_var)
        rn_pass.use_numbers_check.pack(side="left")

        rn_pass.use_symbols_var = tk.BooleanVar()
        rn_pass.use_symbols_check = ttk.Checkbutton(rn_pass.include_chars_frame, text="Symbols", variable=rn_pass.use_symbols_var)
        rn_pass.use_symbols_check.pack(side="left")

        rn_pass.generate_button = ttk.Button(root, text="Generate Password", command=rn_pass.generate_password)
        rn_pass.generate_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        rn_pass.password_label = ttk.Label(root, text="Generated Password:")
        rn_pass.password_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")
        rn_pass.password_var = tk.StringVar()
        rn_pass.password_entry = ttk.Entry(root, textvariable=rn_pass.password_var, state="readonly")
        rn_pass.password_entry.grid(row=6, column=1, padx=10, pady=5)

        rn_pass.copy_button = ttk.Button(root, text="Copy to Clipboard", command=rn_pass.copy_to_clipboard)
        rn_pass.copy_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    def generate_password(rn_pass):
        length = rn_pass.length_entry.get()
        if not length.isdigit() or int(length) <= 0:
            messagebox.showerror("Error", "Password length must be a positive integer.")
            return

        length = int(length)
        complexity = rn_pass.complexity_var.get()
        if complexity == "low":
            use_letters = True
            use_numbers = True
            use_symbols = False
        elif complexity == "medium":
            use_letters = True
            use_numbers = True
            use_symbols = True
        elif complexity == "high":
            use_letters = True
            use_numbers = True
            use_symbols = True

        password = rn_pass.generate_password_helper(length, use_letters, use_numbers, use_symbols)

        if password:
            rn_pass.password_var.set(password)
        else:
            messagebox.showerror("Error", "Please enable at least one character set (letters, numbers, symbols).")

    def generate_password_helper(rn_pass, length, use_letters=True, use_numbers=True, use_symbols=True):
        characters = ''
        if use_letters:
            characters += string.ascii_letters
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        if not characters:
            return None

        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def copy_to_clipboard(rn_pass):
        password = rn_pass.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "No password generated yet.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.minsize(550, 600)
    root.config(bg='grey')
    root.mainloop()
