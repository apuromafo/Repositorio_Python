import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import base64

def convert():
    if var.get():  # Si el checkbox está marcado, decodificar Base64
        base64_text = text_input.get("1.0", tk.END).strip()
        if not base64_text:
            messagebox.showwarning("Warning", "Please enter Base64 text.")
            return
        try:
            decoded_bytes = base64.b64decode(base64_text)
            output_text = decoded_bytes.decode('utf-8')
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, output_text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    else:  # Convertir texto a Base64
        input_text = text_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter text.")
            return
        try:
            base64_bytes = base64.b64encode(input_text.encode('utf-8'))
            base64_string = base64_bytes.decode('utf-8')
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, base64_string)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

def load_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            file_content = file.read()
            base64_string = base64.b64encode(file_content).decode('utf-8')
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, base64_string)

# Configuración de la ventana principal
root = tk.Tk()
root.title("Base64 Converter")
root.geometry("600x400")

# Estilo de la interfaz
frame_input = tk.Frame(root)
frame_input.pack(pady=10)

label_input = tk.Label(frame_input, text="Enter text or Base64:")
label_input.pack()

text_input = scrolledtext.ScrolledText(frame_input, height=10, width=70)
text_input.pack()

# Checkbox para seleccionar la función
var = tk.BooleanVar()
checkbox = tk.Checkbutton(frame_input, text="Decode Base64", variable=var)
checkbox.pack(pady=5)

button_load = tk.Button(frame_input, text="Load File (to Base64)", command=load_file)
button_load.pack(pady=5)

button_convert = tk.Button(frame_input, text="Convert", command=convert)
button_convert.pack(pady=5)

frame_output = tk.Frame(root)
frame_output.pack(pady=10)

label_output = tk.Label(frame_output, text="Output:")
label_output.pack()

text_output = scrolledtext.ScrolledText(frame_output, height=10, width=70)
text_output.pack()

# Ejecutar la ventana
root.mainloop()