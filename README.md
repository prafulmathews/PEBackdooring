To use first compile the binary.


Usage:   .\Backdoor.exe PEfile.exe shellcode.bin


Will write the shellcode in the .reloc section of the PEFile and rewrite the instruction at the entry point with a jump instruction to the starting of the shellcode.


Disclaimer: This tool is intended solely for educational and research purposes only. Using them for any malicious activity is strictly prohibited. The authors of this repository are not responsible for any illegal use or damage caused by these samples/tool.
