import pefile
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from PySide6.QtWidgets import (QApplication, QMainWindow, QFileDialog, QTextEdit, QVBoxLayout, QPushButton, QWidget)
from PySide6.QtGui import QTextCursor

class DLLAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLL Decoder and Analyzer")

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(False)

        self.open_button = QPushButton("Open DLL")
        self.open_button.clicked.connect(self.open_dll)

        self.analyze_button = QPushButton("Analyze DLL")
        self.analyze_button.clicked.connect(self.analyze_dll)

        self.decompile_button = QPushButton("Disassemble Functions")
        self.decompile_button.clicked.connect(self.disassemble_functions)

        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        layout.addWidget(self.open_button)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.decompile_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.file_path = None

    def open_dll(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("DLL Files (*.dll)")

        if file_dialog.exec():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                self.file_path = selected_files[0]
                self.text_edit.append(f"Loaded file: {self.file_path}\n")

    def analyze_dll(self):
        if not self.file_path:
            self.text_edit.append("[ERROR] No file loaded. Please open a DLL file first.\n")
            return

        try:
            pe = pefile.PE(self.file_path)

            self.text_edit.append("\n[+] Basic Information")
            self.text_edit.append(f"  Machine: {hex(pe.FILE_HEADER.Machine)}")
            self.text_edit.append(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
            self.text_edit.append(f"  Time Date Stamp: {pe.FILE_HEADER.TimeDateStamp}\n")

            # Exported functions
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                self.text_edit.append("[+] Exported Functions:")
                self.exported_functions = []
                for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if symbol.name:
                        func_info = {
                            'name': symbol.name.decode(),
                            'address': pe.OPTIONAL_HEADER.ImageBase + symbol.address
                        }
                        self.exported_functions.append(func_info)
                        self.text_edit.append(f"  {hex(func_info['address'])} {func_info['name']}")
            else:
                self.text_edit.append("[!] No exported functions found.")

            self.text_edit.append("")

            # Imported functions
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.text_edit.append("[+] Imported Libraries and Functions:")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    self.text_edit.append(f"  {entry.dll.decode()}")
                    for imp in entry.imports:
                        self.text_edit.append(f"    {hex(imp.address)} {imp.name.decode() if imp.name else ''}")
            else:
                self.text_edit.append("[!] No imported functions found.")

        except pefile.PEFormatError as e:
            self.text_edit.append(f"[ERROR] Unable to parse the DLL file: {e}\n")

    def disassemble_functions(self):
        if not self.file_path:
            self.text_edit.append("[ERROR] No file loaded. Please open a DLL file first.\n")
            return

        if not hasattr(self, 'exported_functions') or not self.exported_functions:
            self.text_edit.append("[ERROR] No exported functions to disassemble. Please analyze the DLL first.\n")
            return

        try:
            pe = pefile.PE(self.file_path)

            # Determine architecture (32-bit or 64-bit)
            if pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
                self.text_edit.append("[INFO] Disassembling in 64-bit mode.")
            elif pe.FILE_HEADER.Machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
                self.text_edit.append("[INFO] Disassembling in 32-bit mode.")
            else:
                self.text_edit.append("[ERROR] Unsupported architecture for disassembly.\n")
                return

            for func in self.exported_functions:
                func_address = func['address']
                section = next((s for s in pe.sections if s.VirtualAddress <= func_address - pe.OPTIONAL_HEADER.ImageBase < s.VirtualAddress + s.Misc_VirtualSize), None)
                if not section:
                    self.text_edit.append(f"[ERROR] Could not locate section for function {func['name']} at {hex(func_address)}.\n")
                    continue

                raw_offset = func_address - pe.OPTIONAL_HEADER.ImageBase - section.VirtualAddress + section.PointerToRawData
                code = pe.get_memory_mapped_image()[raw_offset:raw_offset + 64]  # Read 64 bytes for disassembly

                self.text_edit.append(f"\n[+] Disassembly for {func['name']} at {hex(func_address)}:")
                for i in cs.disasm(code, func_address):
                    self.text_edit.append(f"  {hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")

        except Exception as e:
            self.text_edit.append(f"[ERROR] Failed to disassemble functions: {e}\n")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = DLLAnalyzerApp()
    main_window.show()
    sys.exit(app.exec())