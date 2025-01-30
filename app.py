from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from io import BytesIO
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

app = Flask(__name__)

# Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename, is_encryption=True):
    if is_encryption:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    else:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'bin'}
    
def derive_aes_key(key: str):
    return hashlib.sha256(key.encode()).digest()

class SecureImageProcessor:
    def __init__(self, image_stream=None):
        self.image = None
        if image_stream:
            self.image = Image.open(image_stream)

    def encrypt_image(self, key):
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
        img_array = np.array(self.image)
        padded_data = pad(img_array.tobytes(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        shape_metadata = np.array(img_array.shape, dtype=np.int32).tobytes()
        return shape_metadata + encrypted_data

    def decrypt_image(self, encrypted_data, key, shape):
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        img_array = np.frombuffer(decrypted_data, dtype=np.uint8).reshape(shape)
        return Image.fromarray(img_array)

@app.route('/')
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <title>Secure Image Processor</title>

    <style>
        body {
            background-color: #0A1828;
            background-size: cover;
            background-position: center;
            font-family: 'Trebuchet MS', sans-serif;
        }

        .typed-out {
            overflow: hidden;
            border-right: .15em solid blue;
            white-space: nowrap;
            animation: typing 1s steps(10, end) forwards, blinking .8s infinite;
            font-size: 1.8rem;
            width: 0;
            display: inline-block;
        }

        @keyframes typing {
            from { width: 0 }
            to { width: 22% }
        }

        @keyframes blinking {
            from { border-color: transparent }
            to { border-color: blue; }
        }

        header {
            text-align: center;
            margin-bottom: 8px;
            color: #BFA181;
            padding: 10rem;
        }

        h1 {
            letter-spacing: 10px;
            font-size: 4rem;
        }

        .typed-container {
            text-align: center;
        }

        .container {
            display: flex;
            justify-content: center;
            gap: 10rem;
            flex-wrap: wrap;
        }

        section {
            flex: 1;
            max-width: 500px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        form {
            background-color: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.3);
            transition: box-shadow 0.3s ease-in-out, transform 0.3s ease;
        }

        form:hover {
            box-shadow: 0px 6px 16px rgba(191, 161, 129, 0.6);
            transform: translateY(-4px);
        }

        button {
            transition: all 0.3s ease-in-out;
            font-weight: bold;
        }

        button:hover {
            transform: scale(1.05);
            box-shadow: 0px 4px 10px rgba(255, 255, 255, 0.3);
        }

        .encrypt-btn {
            background-color: #2563EB;
            color: white;
            padding: 10px 16px;
            border-radius: 6px;
        }

        .encrypt-btn:hover {
            background-color: #1E40AF;
        }

        .decrypt-btn {
            background-color: #16A34A;
            color: white;
            padding: 10px 16px;
            border-radius: 6px;
        }

        .decrypt-btn:hover {
            background-color: #15803D;
        }
    </style>
</head>
<body>
    <header>
        <h1 class="text-5xl font-bold">SecureSnap</h1>
        <p class="text-lg">Protect your images with military-grade encryption</p>
        <div class="typed-container">
            <div class="typed-out">Pixel Slice Stitch</div>
        </div>
    </header>

    <div class="container mx-auto p-8 text-gray-900">
        <div class="container">
            <section>
                <h2 class="text-2xl font-semibold mb-4 text-[#BFA181]">Encrypt an Image</h2>
                <form id="encrypt-form" method="POST" action="/upload" enctype="multipart/form-data">
                    <svg width="50" height="50" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="mx-auto mb-4">
                        <path d="M12 2C8.13 2 5 5.13 5 9V12H4C2.89 12 2 12.89 2 14V20C2 21.11 2.89 22 4 22H20C21.11 22 22 21.11 22 20V14C22 12.89 21.11 12 20 12H19V9C19 5.13 15.87 2 12 2ZM12 4C14.76 4 17 6.24 17 9V12H7V9C7 6.24 9.24 4 12 4Z" fill="#2563EB"/>
                    </svg>
                    <label class="block mb-2 font-medium text-gray">Upload Image:</label>
                    <input type="file" name="encrypt-file" accept="image/*" class="mb-4 block w-full border border-gray-300 p-2 rounded" required>
                    <label class="block mb-2 font-medium">Security Key:</label>
                    <input type="password" name="key" class="mb-4 block w-full border border-gray-300 p-2 rounded text-gray-900" placeholder="Enter your security key" required>
                    <button type="submit" class="encrypt-btn">Encrypt</button>
                </form>
                <div id="encrypt-result" class="mt-4"></div>
            </section>

            <section>
                <h2 class="text-2xl font-semibold mb-4 text-[#BFA181]">Decrypt an Image</h2>
                <form id="decrypt-form" method="POST" action="/decrypt" enctype="multipart/form-data">
                    <svg width="50" height="50" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="mx-auto mb-4">
                        <path d="M12 2C8.13 2 5 5.13 5 9V12H4C2.89 12 2 12.89 2 14V20C2 21.11 2.89 22 4 22H20C21.11 22 22 21.11 22 20V14C22 12.89 21.11 12 20 12H19V9C19 5.13 15.87 2 12 2ZM12 4C14.76 4 17 6.24 17 9V12H7V9C7 6.24 9.24 4 12 4Z" fill="#16A34A"/>
                    </svg>
                    <label class="block mb-2 font-medium">Upload Encrypted File:</label>
                    <input type="file" name="decrypt-file" accept="application/octet-stream" class="mb-4 block w-full border border-gray-300 p-2 rounded" required>
                    <label class="block mb-2 font-medium">Security Key:</label>
                    <input type="password" name="key" class="mb-4 block w-full border border-gray-300 p-2 rounded" placeholder="Enter your security key" required>
                    <button type="submit" class="decrypt-btn">Decrypt</button>
                </form>
                <div id="decrypt-result" class="mt-4"></div>
            </section>
        </div>
        <footer class="text-center mt-2 text-[#BFA181]">
            <p class="text-md">Created with ❤️ by SecureSnap Team</p>
        </footer>
    </div>
</body>
</html>"""

@app.route('/upload', methods=['POST'])
def upload_image():
    if 'encrypt-file' not in request.files or 'key' not in request.form:
        return jsonify({'message': 'File and key are required'}), 400

    file = request.files['encrypt-file']
    key = request.form['key']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    processor = SecureImageProcessor(file)
    encrypted_data = processor.encrypt_image(derive_aes_key(key))

    buffer = BytesIO()
    buffer.write(encrypted_data)
    buffer.seek(0)

    return send_file(buffer, mimetype='application/octet-stream', as_attachment=True, download_name='encrypted_image.bin')

@app.route('/decrypt', methods=['POST'])
def decrypt_image():
    if 'decrypt-file' not in request.files or 'key' not in request.form:
        return jsonify({'message': 'File, key, and shape are required'}), 400

    file = request.files['decrypt-file']
    key = request.form['key']

    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400

    # Ensure the file is valid for decryption
    if not file.filename.endswith('.bin'):
        return jsonify({'message': 'Invalid file format for decryption'}), 400

    try:
        # Read encrypted data from the uploaded file
        encrypted_data = file.read()

        # Extract the shape from the first 12 bytes of the file
        shape_metadata = encrypted_data[:12]  # 3 integers (4 bytes each)
        shape = tuple(np.frombuffer(shape_metadata, dtype=np.int32))

        # Decrypt the remaining data
        encrypted_image_data = encrypted_data[12:]
        processor = SecureImageProcessor()  # Placeholder image not used
        decrypted_image = processor.decrypt_image(encrypted_image_data, derive_aes_key(key), shape)

        # Return the decrypted image
        buffer = BytesIO()
        decrypted_image.save(buffer, format='PNG')
        buffer.seek(0)

        return send_file(buffer, mimetype='image/png', as_attachment=True, download_name='decrypted_image.png')

    except Exception:
        return jsonify({'message': 'Cannot decode'}), 400

if __name__ == '__main__':
    app.run(debug=True)
