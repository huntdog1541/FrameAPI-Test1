from keystone import *
import sys
from flask import *

app = Flask(__name__)

ks_arch_dict = {
    "X86": KS_ARCH_X86,
    "ARM": KS_ARCH_ARM,
    "ARM64": KS_ARCH_ARM64,
    "EVM": KS_ARCH_EVM,
    "MIPS": KS_ARCH_MIPS,
    "PPC": KS_ARCH_PPC,
    "SPARC": KS_ARCH_SPARC
}

ks_mode_dict = {
    "X16": KS_MODE_16,
    "X32": KS_MODE_32,
    "X64": KS_MODE_64,
    "ARM": KS_MODE_ARM,
    "THUMB": KS_MODE_THUMB,
    "MICRO": KS_MODE_MICRO,
    "MIPS3": KS_MODE_MIPS3,
    "MIPS32R6": KS_MODE_MIPS32R6,
    "V8": KS_MODE_V8,
    "V9": KS_MODE_V9,
    "QPX": KS_MODE_QPX
}


def get_arch(arch_str):
    return ks_arch_dict[arch_str]


def get_mode(mode_str):
    return ks_mode_dict[mode_str]


def get_arch_str(arch_val):
    for x in ks_arch_dict:
        if arch_val == ks_arch_dict[x]:
            return x
    return None


def get_mode_str(mode_val):
    for x in ks_mode_dict:
        if mode_val == ks_mode_dict[x]:
            return x
    return None


def keystone_execute(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    instructions = []
    machine_code = []

    encoding, count = ks.asm(code)

    print("%s = [ " % code, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


@app.route('/')
def status():
    return 'Up and Running'


@app.route('/api', methods=['GET', 'POST'])
def get_assembly():
    json = request.get_json()
    arch = validate_architecture(json)
    mode = validate_mode(json)
    inst = validate_instructions(json)

    keystone_execute(arch, mode, inst)

    return 'Get Assembly'


def validate_architecture(json):
    if json.get('architecture') is not None:
        print('Arch: %s' % json.get('architecture'), file=sys.stderr)
        try:
            return get_arch(json.get('architecture').upper())
        except KeyError:
            return f"ERROR: {json.get('architecture')} is not a supported architecture"
    else:
        return 'ERROR: architecture is none, architecture is required'


def validate_mode(json):
    if json.get('mode') is not None:
        print('Mode: %s' % json.get('mode'), file=sys.stderr)
        try:
            return get_mode(json.get('mode').upper())
        except KeyError:
            return f"ERROR: {json.get('mode')} is not supported mode"
    else:
        return f"ERROR: mode is none, mode is required"


def validate_instructions(json):
    if json.get('instructions') is not None:
        print('Instructions: %s ' % json.get('instructions'))
        return json.get('instructions')
    else:
        return f"ERROR: instructions is none, instructions are required"


""" def ks_execute(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax
    
    encoding, count = ks.asm(code)
    answer = [code]

    hex_string = [] """

if __name__ == '__main__':
    keystone_execute(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx")
