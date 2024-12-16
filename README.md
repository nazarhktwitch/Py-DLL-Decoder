# Py DLL Decoder

This application allows users to analyze and disassemble DLL files. It provides basic insights into the structure of DLL files, including imported and exported functions, and offers a basic disassembly feature for exported functions.

## Features

- **Open DLL Files**: Load a DLL file for analysis.
- **Analyze DLL**:
  - View machine architecture and basic header information.
  - Display a list of exported functions and their addresses.
  - Display a list of imported libraries and functions.
- **Disassemble Functions**:
  - Disassemble the first 64 bytes of exported functions using the Capstone library.
  - Automatically detect the architecture (32-bit or 64-bit) for accurate disassembly.
- **Dissasambler with Popular Decompilers**:
  - Integrate with online tools like Dogbolt to analyze DLLs using multiple decompilers (e.g., angr, Binary Ninja, Ghidra, and Hex-Rays).
  - Upload DLLs directly and retrieve analysis results for different decompilers.

## Requirements

To run this application, ensure you have the following installed:

- Python 3.8 or higher
- The following Python libraries:
  - `pefile`
  - `capstone`
  - `PySide6`
  - `requests`

## Installation

1. Clone this repository or download the source code.

   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. Install the required dependencies using pip:

   ```bash
   pip install pefile capstone PySide6
   ```

Or from requirements.txt:

  ```bash
  pip install -r requirements.txt
  ```

## Usage

1. Run the application:

   ```bash
   python dll_decoder.py
   ```

2. Use the GUI to:
   - Load a DLL file by clicking **Open DLL**.
   - Analyze the DLL by clicking **Analyze DLL**.
   - Disassemble exported functions by clicking **Disassemble Functions**.
   - Upload DLL to popular decompilers and view results by clicking **Dissasambler with Popular Decompilers**.

## How It Works

### Analyze DLL

- The application uses the `pefile` library to parse the Portable Executable (PE) format of DLL files.
- Extracts and displays:
  - Basic file headers.
  - Exported and imported functions.

### Disassemble Functions

- The application uses the `capstone` library to disassemble machine code of exported functions.
- Automatically detects the architecture (32-bit or 64-bit) based on the PE file header.

### Dissasambler with Popular Decompilers

- The application integrates with the Dogbolt platform using the `requests` library.
- DLL files are uploaded to the service, and results are fetched for the following decompilers:
  - angr
  - Binary Ninja
  - Ghidra
  - Hex-Rays
- Results are displayed in the application for comparison and further analysis.

## Limitations

- Only disassembles the first 64 bytes of exported functions.
- Does not provide a full decompiler, but rather a basic disassembly view.
- Limited to analyzing the structure and exports/imports of DLL files.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contribution

Feel free to submit issues or pull requests to improve this project. Contributions are welcome!
