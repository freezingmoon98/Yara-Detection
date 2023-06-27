import os
import sys
import pefile
import subprocess
import capstone
import logging
import yara
import shutil
import argparse
#never run malware analysis outside of sandbox

# Get the directory path of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Add the Yara rules directory to the script's path
yara_rules_dir = os.path.join(script_dir, "yara_rules")  # Replace "yara_rules" with your Yara rules directory
sys.path.append(yara_rules_dir)



def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='malware_analysis.log', level=logging.INFO, format=log_format)

def log_info(message):
    logging.info(message)

def log_error(message):
    logging.error(message)

def analyze_file(file_path):
    if not os.path.exists(file_path):
        log_error("File not found: {}".format(file_path))
        return

    try:
        # File Analysis
        pe = pefile.PE(file_path)
        log_info("File Name: {}".format(os.path.basename(file_path)))
        log_info("ImageBase: 0x{:08x}".format(pe.OPTIONAL_HEADER.ImageBase))
        log_info("Entry Point: 0x{:08x}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        log_info("Sections:")
        for section in pe.sections:
            log_info("   Name: {}".format(section.Name.decode().strip('\x00')))
            log_info("   Virtual Address: 0x{:08x}".format(section.VirtualAddress))
            log_info("   Size: 0x{:08x}".format(section.SizeOfRawData))
            log_info("")
# add your sandbox here and add code again to file. Never open files without sandbox
        # # Behavior Monitoring
        # sandbox_path = os.path.join(script_dir, "sandbox")  # Replace "sandbox" with the path to your sandbox environment
        # sandbox_file = os.path.join(sandbox_path, os.path.basename(file_path))
        # shutil.copy2(file_path, sandbox_file)
        # subprocess.Popen([sandbox_file], cwd=sandbox_path)

        # Code Disassembly
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        code = pe.get_memory_mapped_image()[pe.OPTIONAL_HEADER.AddressOfEntryPoint:]
        log_info("Code Disassembly:")
        for insn in md.disasm(code, pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint):
            log_info("   0x{:08x}:  {}  {}".format(insn.address, insn.mnemonic, insn.op_str))

        # Yara Scanning
        rules_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yara")
        rules = yara.compile(rules_file)
        matches = rules.match(file_path)
        if matches:
            log_info("Yara Matches:")
            for match in matches:
                log_info("   Rule Name: {}".format(match.rule))
                log_info("   Tags: {}".format(match.tags))
                log_info("   Meta: {}".format(match.meta))
                log_info("")

    except pefile.PEFormatError as e:
        log_error("Error parsing the PE file: {}".format(str(e)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", help="Path to the file or directory that should be checked")
    args = parser.parse_args()

    # Setup logging
    setup_logging()

    # Check if the given path is a file or directory
    if os.path.isfile(args.path):
        # Analyze the single file
        analyze_file(args.path)
    elif os.path.isdir(args.path):
        # Analyze all files in the directory
        for root, _, files in os.walk(args.path):
            for file in files:
                file_path = os.path.join(root, file)
                analyze_file(file_path)
    else:
        log_error("Invalid path: {}".format(args.path))

if __name__ == '__main__':
    main()
