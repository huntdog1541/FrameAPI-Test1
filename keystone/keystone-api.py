from keystone import * 
import sys 
from flask import * 


app = Flask(__name__)


ks_arch_dict = {
    "X86": KS_ARCH_X86,
    "ARM": KS_ARCH_ARM,
    "ARM64": KS_ARCH_ARM64,
    "EVM": KS_ARCH_EVM,
    "M68K": KS_ARCH_M68K,
    "M680X": KS_ARCH_M680X,
    "MIPS": KS_ARCH_MIPS,
    "MOS65XX": KS_ARCH_MOS65XX,
    "PPC": KS_ARCH_PPC,
    "SPARC": KS_ARCH_SPARC,
    "SYSZ": KS_ARCH_SYSZ,
    "TMS320C64X": KS_ARCH_TMS320C64X,
    "XCORE": KS_ARCH_XCORE
}

ks_mode_dict = {
    "X16": KS_MODE_16,
    "X32": KS_MODE_32,
    "X64": KS_MODE_64,
    "ARM": KS_MODE_ARM,
    "THUMB": KS_MODE_THUMB,
    "MCLASS": KS_MODE_MCLASS,
    "MICRO": KS_MODE_MICRO,
    "MIPS3": KS_MODE_MIPS3,
    "MIPS32R6": KS_MODE_MIPS32R6,
    "MIPS2": KS_MODE_MIPS2,
    "V8": KS_MODE_V8,
    "V9": KS_MODE_V9,
    "QPX": KS_MODE_QPX,
    "M68K_000": KS_MODE_M68K_000,
    "M68K_010": KS_MODE_M68K_010,
    "M68K_020": KS_MODE_M68K_020,
    "M68K_030": KS_MODE_M68K_030,
    "M68K_040": KS_MODE_M68K_040,
    "M68K_060": KS_MODE_M68K_060,
    "M680X_6301": KS_MODE_M680X_6301,
    "M680X_6309": KS_MODE_M680X_6309,
    "M680X_6800": KS_MODE_M680X_6800,
    "M680X_6801": KS_MODE_M680X_6801,
    "M680X_6805": KS_MODE_M680X_6805,
    "M680X_6808": KS_MODE_M680X_6808,
    "M680X_6809": KS_MODE_M680X_6809,
    "M680X_6811": KS_MODE_M680X_6811,
    "M680X_CPU12": KS_MODE_M680X_CPU12,
    "M680X_HCS08": KS_MODE_M680X_HCS08,

}

def keystone_execute(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    encoding, count = ks.asm(code)

    print("%s = [ " % code, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


@app.route('/api', methods=['GET', 'POST'])
def get_assembly():
    json = request.get_json()
    if json.get('architecture') is not None:
        print('Arch %s ' % json.get('architecture'), file=sys.stderr)
    if json.get('mode') is not None:
        print('Mode %s ' % json.get('mode'), file=sys.stderr)
    if json.get('instructions') is not None:
        print('Instructions %s ' % json.get('instructions'), file=sys.stderr)
    
    return 'Get Assembly'

""" def ks_execute(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax
    
    encoding, count = ks.asm(code)
    answer = [code]

    hex_string = [] """

if __name__ == '__main__':
    keystone_execute(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx")