import binascii
from json import JSONEncoder

from flask import Flask, request, jsonify
import sys
from capstone import * 

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def status():
    return 'Up and Running'


cs_arch_dict = {
    "X86": CS_ARCH_X86,
    "ARM": CS_ARCH_ARM,
    "ARM64": CS_ARCH_ARM64,
    "EVM": CS_ARCH_EVM,
    "M68K": CS_ARCH_M68K,
    "M680X": CS_ARCH_M680X,
    "MIPS": CS_ARCH_MIPS,
    "MOS65XX": CS_ARCH_MOS65XX,
    "PPC": CS_ARCH_PPC,
    "SPARC": CS_ARCH_SPARC,
    "SYSZ": CS_ARCH_SYSZ,
    "TMS320C64X": CS_ARCH_TMS320C64X,
    "XCORE": CS_ARCH_XCORE
}

cs_mode_dict = {
    "X16": CS_MODE_16,
    "X32": CS_MODE_32,
    "X64": CS_MODE_64,
    "ARM": CS_MODE_ARM,
    "THUMB": CS_MODE_THUMB,
    "MCLASS": CS_MODE_MCLASS,
    "MICRO": CS_MODE_MICRO,
    "MIPS3": CS_MODE_MIPS3,
    "MIPS32R6": CS_MODE_MIPS32R6,
    "MIPS2": CS_MODE_MIPS2,
    "V8": CS_MODE_V8,
    "V9": CS_MODE_V9,
    "QPX": CS_MODE_QPX,
    "M68K_000": CS_MODE_M68K_000,
    "M68K_010": CS_MODE_M68K_010,
    "M68K_020": CS_MODE_M68K_020,
    "M68K_030": CS_MODE_M68K_030,
    "M68K_040": CS_MODE_M68K_040,
    "M68K_060": CS_MODE_M68K_060,
    "M680X_6301": CS_MODE_M680X_6301,
    "M680X_6309": CS_MODE_M680X_6309,
    "M680X_6800": CS_MODE_M680X_6800,
    "M680X_6801": CS_MODE_M680X_6801,
    "M680X_6805": CS_MODE_M680X_6805,
    "M680X_6808": CS_MODE_M680X_6808,
    "M680X_6809": CS_MODE_M680X_6809,
    "M680X_6811": CS_MODE_M680X_6811,
    "M680X_CPU12": CS_MODE_M680X_CPU12,
    "M680X_HCS08": CS_MODE_M680X_HCS08,

}


def get_arch(arch_str):
    return cs_arch_dict[arch_str]


def get_mode(mode_str):
    return cs_mode_dict[mode_str]


def get_arch_str(arch_val):
    for x in cs_arch_dict:
        if arch_val == cs_arch_dict[x]:
            return x
    return None


def get_mode_str(mode_val):
    for x in cs_mode_dict:
        if mode_val == cs_mode_dict[x]:
            return x
    return None


@app.route('/api', methods=['GET', 'POST'])
def get_code():
    print('Request %s' % request, file=sys.stderr)
    json = request.get_json()
    if json.get('architecture') is not None:
        print('Arch %s' % json.get('architecture'), file=sys.stderr)
        try:
            arch = get_arch(json.get('architecture').upper())
        except KeyError:
            return f"ERROR: {json.get('architecture')} is not a supported architecture"
    else:
        return 'ERROR: architecture is none, architecture is required'

    if json.get('mode') is not None:
        print('Mode %s' % json.get('mode'), file=sys.stderr)
        try:
            mode = get_mode(json.get('mode').upper())
        except KeyError:
            return f"ERROR: {json.get('mode')} is not a supported mode"
    else:
        return 'ERROR: mode is none, mode is required'

    if json.get('hex') is not None:
        print('Hex: %s' % json.get('hex'), file=sys.stderr)
    else:
        return f"ERROR: hex is none, hex is required to execute"

    hex_string = json.get('hex')
    res_string = capstone(arch, mode, hex_string, syntax='intel')

    return res_string


def capstone(arch, mode, hex, syntax):
    hex_bytes = binascii.unhexlify(hex)                                 # Convert a string of hex to a byte string 
    print('Bytes: %s' % binascii.hexlify(hex_bytes, '-'), file=sys.stderr) 
    machine_code = []
    instructions = []
    operands = []
    addresses = []
    byte_size = [] 

    print('----------------------------------------------------------------', file=sys.stderr)

    # Execute the capstone  
    md = Cs(arch, mode)
    for insn in md.disasm(hex_bytes, 0x0000):                           # Go through the array return after a successful execution
        print('Insn Bytes: %s ' % insn.bytes, file=sys.stderr)
        machine_code.append(binascii.hexlify(insn.bytes, '-').decode('utf-8'))   # Convert bytes into an hex array 
        print('Insn: %s ' % insn.mnemonic, file=sys.stderr)
        instructions.append(insn.mnemonic)                       # Instructions that were disassembled
        print('Operand: %s ' % insn.op_str, file=sys.stderr)
        operands.append(insn.op_str)                             # Operands 
        print('Size: %s ' % insn.size, file=sys.stderr)
        byte_size.append(insn.size)                              # the number of bytes 
        print('Address: %s ' % insn.address, file=sys.stderr)
        addresses.append(insn.address)                           # the next start address
        print('----------------------------------------------------------------', file=sys.stderr)

    # Generate the data object that is return as a json
    data = {
        'arch': get_arch_str(arch),
        'mode': get_mode_str(mode),
        'hex': hex,
        'result': {
            'machine_code': machine_code,
            'instructions': instructions,
            'operands': operands,
            'byte_size': byte_size,
            'addresses': addresses
        }
    }

    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
