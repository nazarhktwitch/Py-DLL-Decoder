# DLL/ELF Decoder and Analyzer

This application allows you to analyze DLL (PE) and ELF binary files, disassemble their functions, and extract information about the sections, exported functions, and imported libraries. It utilizes **Capstone** for disassembly, **Unicorn** for emulation, and **pyelftools** for parsing ELF files.

## Features
- **Analyze DLL files (PE format)**: Extracts and displays information about the file, sections, exported functions, and imported libraries.
- **Analyze ELF files**: Extracts section details, including the `.text` section where code resides.
- **Disassemble functions**: Using **Capstone** to disassemble exported functions in DLL files and emulate code using **Unicorn** in ELF files.
- **Support for both 32-bit and 64-bit architectures**.

## Requirements
Before running the application, make sure you have the following Python libraries installed:

- **PySide6**
- **Capstone**
- **Unicorn**
- **pyelftools**
- **pefile**
- **pyqt6**

### Install dependencies

```bash
pip install pefile PySide6 capstone unicorn pyelftools pyqt6
```

Or from requirements.txt:

```bash
pip install -r requirements.txt
```
