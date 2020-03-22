import binascii
from json import JSONEncoder

from flask import Flask, request, jsonify
import sys
from capstone import * 

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World!'


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
    "X64": CS_MODE_64
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


@app.route('/api')
def get_code():
    print('Request %s' % request, file=sys.stderr)
    arch = CS_ARCH_X86
    mode = CS_MODE_32
    json = request.get_json()
    if json.get('architecture') is not None:
        print('Arch %s' % json.get('architecture'), file=sys.stderr)
        arch = get_arch(json.get('architecture').upper())
        print('Get Arch String: %s ' % get_arch_str(arch), file=sys.stderr)
    if json.get('mode') is not None:
        print('Mode %s' % json.get('mode'), file=sys.stderr)
        mode = get_mode(json.get('mode').upper())
        print('Get Mode String: %s ' % get_mode_str(mode), file=sys.stderr)

    if json.get('hex') is not None:
        print('Hex: %s' % json.get('hex'), file=sys.stderr)
        # hex = json.get('hex')
    print('Arch %s' % json.get('arch'), file=sys.stderr)
    print('Mode %s' % json.get('mode'), file=sys.stderr)
    print('Hex: %s' % json.get('hex'), file=sys.stderr)
    hex_string = json.get('hex')
    res_string = capstone(arch, mode, hex_string, syntax='intel')

    return res_string


class Result():
    def __init__(self):
        pass

    machine_code = []
    instructions = []
    operands = []
    addresses = []
    byte_size = []


def capstone(arch, mode, hex, syntax):
    hex_bytes = binascii.unhexlify(hex)                                 # Convert a string of hex to a byte string 
    print('Bytes: %s' % binascii.hexlify(hex_bytes, '-'), file=sys.stderr) 
    result = Result(); 

    # Execute the capstone  
    md = Cs(arch, mode)
    for insn in md.disasm(hex_bytes, 0x0000):                           # Go through the array return after a successful execution
        print('Insn Bytes: %s ' % insn.bytes, file=sys.stderr)
        result.machine_code.append(binascii.hexlify(insn.bytes, '-'))   # Convert bytes into an hex array 
        print('Insn: %s ' % insn.mnemonic, file=sys.stderr)
        result.instructions.append(insn.mnemonic)                       # Instructions that were disassembled
        print('Operand: %s ' % insn.op_str, file=sys.stderr)
        result.operands.append(insn.op_str)                             # Operands 
        print('Size: %s ' % insn.size, file=sys.stderr)
        result.byte_size.append(insn.size)                              # the number of bytes 
        print('Address: %s ' % insn.address, file=sys.stderr)
        result.addresses.append(insn.address)                           # the next start address 

    # Generate the data object that is return as a json
    data = {
        'arch': get_arch_str(arch),
        'mode': get_mode_str(mode),
        'result': {
            'mach_code': result.machine_code,
            'instructions': result.instructions,
            'operands': result.operands,
            'byte_size': result.byte_size,
            'addresses': result.addresses
        }
    }

    return jsonify(data)


def generate_result_json(data):
    return {
        'mach_code': data.machine_code,
        'instructions': data.instructions,
        'operands': data.operands,
        'byte_size': data.byte_size,
        'addresses': data.addresses
    }


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
