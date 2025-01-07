# CipherLens
CipherLens is an intelligent image encryption and decryption system that combines cutting-edge security, simplicity, and scalability. It leverages advanced cryptographic algorithms and a user-friendly GUI to protect sensitive visual data from unauthorized access.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [Future Plans](#future-plans)
- [Contributing](#contributing)
- [License](#license)

---

## Introduction
With the rise of cybersecurity threats and over 20 million data breaches reported annually, securing image data has become a critical need. CipherLens addresses this challenge by providing an unpredictable and autonomous encryption system that requires no technical expertise to use.

## Features
### Key Functionalities:
- **Randomized Algorithm Selection:** Automatically selects from AES, Blowfish, or Triple DES to ensure unpredictability.
- **Random Seed Integration:** Prevents predictability across encryption processes.
- **Real-Time Feedback:** Displays status messages like "Image Loaded," "Encryption Successful," and "Decryption Successful."
- **Error Handling:** Alerts users to incorrect keys or mismatched decryption attempts.
- **Visual Comparison:** Offers a side-by-side display of original, encrypted, and decrypted images.

### Advanced Technical Features:
- **Padding and Compatibility:** Ensures data aligns with algorithm requirements.
- **Metadata Management:** Stores encryption details for consistent decryption.
- **Seed Persistence:** Maintains randomness across sessions for secure reproducibility.

### User Experience:
- Comprehensive GUI for ease of use.
- Displays operation times for performance evaluation.

## Technologies Used
- **Programming Language:** Python
- **Cryptography Algorithms:** AES, Blowfish, Triple DES
- **Frameworks and Libraries:**
  - GUI: Tkinter (or equivalent GUI library)
  - Cryptography: `pycryptodome`
  - Image Processing: `Pillow`

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/CipherLens.git
   ```
2. Navigate to the project directory:
   ```bash
   cd CipherLens
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python main.py
   ```

## Usage
1. Launch the application.
2. Load an image to encrypt.
3. Click the "Encrypt" button to secure the image.
4. Save the encrypted image and note the key.
5. Use the "Decrypt" button with the correct key to retrieve the original image.

## Future Plans
- **Web Integration:** Develop a Flask-based web platform for broader access.
- **Cloud Integration:** Support encrypted uploads and retrieval from cloud storage.
- **Mobile-Friendly Version:** Create smartphone apps for on-the-go security.
- **Enhanced Features:** Allow manual algorithm selection and encryption strength customization.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork this repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add feature description'
   ```
4. Push to the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

## License
This project is licensed under the [MIT License](LICENSE).
