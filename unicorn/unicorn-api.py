import binascii

from flask import Flask, request, jsonify
from unicorn import *
from unicorn.x86_const import *
import sys

app = Flask(__name__)


@app.route('/')
def test():
    return 'Unicorn is running'


uc_arch_dict = {
    "X86": UC_ARCH_X86
}

uc_mode_dict = {
    "X16": UC_MODE_16,
    "X32": UC_MODE_32,
    "X64": UC_MODE_64
}


def get_arch(arch_str):
    return uc_arch_dict[arch_str]


def get_mode(mode_str):
    return uc_mode_dict[mode_str]


def get_arch_str(arch_val):
    for x in uc_arch_dict:
        if arch_val == uc_arch_dict[x]:
            return x
    return None


def get_mode_str(mode_val):
    for x in uc_mode_dict:
        if mode_val == uc_mode_dict[x]:
            return x
    return None


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    print(">>> --- EFLAGS is 0x%x" % eflags)


def hook_code64(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> RIP is 0x%x" % rip);


# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
              % (address, size, value))
        # map this memory in with 2MB in size
        uc.mem_map(0xaaaa0000, 2 * 1024 * 1024)
        # return True to indicate we want to continue emulation
        return True
    else:
        # return False to indicate we want to stop emulation
        return False


# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
              % (address, size, value))
    else:  # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" \
              % (address, size))


# callback for IN instruction
def hook_in(uc, port, size, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)
    print("--- reading from port 0x%x, size: %u, address: 0x%x" % (port, size, eip))
    if size == 1:
        # read 1 byte to AL
        return 0xf1
    if size == 2:
        # read 2 byte to AX
        return 0xf2
    if size == 4:
        # read 4 byte to EAX
        return 0xf4
    # we should never reach here
    return 0


# callback for OUT instruction
def hook_out(uc, port, size, value, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)
    print("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x" % (port, size, value, eip))

    # confirm that value is indeed the value of AL/AX/EAX
    v = 0
    if size == 1:
        # read 1 byte in AL
        v = uc.reg_read(UC_X86_REG_AL)
    if size == 2:
        # read 2 bytes in AX
        v = uc.reg_read(UC_X86_REG_AX)
    if size == 4:
        # read 4 bytes in EAX
        v = uc.reg_read(UC_X86_REG_EAX)

    print("--- register value = 0x%x" % v)


@app.route('/api')
def post_request():
    print('Request %s ' % request, file=sys.stderr)
    json = request.get_json()
    if json.get('architecture') is not None:
        print('Architecture %s ' % json.get('architecture'), file=sys.stderr)
    if json.get('mode') is not None:
        print('Mode %s ' % json.get('mode'), file=sys.stderr)
    if json.get('code') is not None:
        print('Code %s ' % json.get('code'), file=sys.stderr)
        code_bytes = binascii.unhexlify(json.get('code'))
        print('Bytes: %s ' % binascii.hexlify(code_bytes), file=sys.stderr)
        arch = json.get('architecture')
        mode = json.get('mode')
        syntax = 'INTEL'
        unicorn(arch, mode, code_bytes, syntax)
    return 'Unicorn'


def check_request_code(json):
    if json.get('code') is not None:
        print('Code %s ' % json.get('code'), file=sys.stderr)
        try:
            code_bytes = binascii.unhexlify(json.get('code'))
            print('Bytes: %s ' % binascii.hexlify(code_bytes), file=sys.stderr)
        except binascii.Error:
            return binascii.Error, f"ERROR: {json.get('code')} is not formatted right"
    else:
        return 'ERROR: code is none, code is required'


def check_request_arch(json):
    if json.get('architecture') is not None:
        print('Arch %s' % json.get('architecture'), file=sys.stderr)
        try:
            return get_arch(json.get('architecture').upper())
        except KeyError:
            return KeyError, f"ERROR: {json.get('architecture')} is not a supported architecture"
    else:
        return 'ERROR: architecture is none, architecture is required'


def check_request_mode(json):
    if json.get('mode') is not None:
        print('Mode %s ' % json.get('mode'), file=sys.stderr)
        try:
            return get_mode(json.get('mode').upper())
        except KeyError:
            return KeyError, f"ERROR: {json.get('mode')} is not a supported mode"
    else:
        return 'ERROR: mode is none, mode is required'


def unicorn(arch, mode, code, syntax):
    addresses = []
    byte_size = []
    # memory address where emulation starts
    ADDRESS = 0x1000000

    print("Emulate i386 code")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2 MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        mu.reg_write(UC_X86_REG_XMM0, 0x000102030405060708090a0b0c0d0e0f)
        mu.reg_write(UC_X86_REG_XMM1, 0x00102030405060708090a0b0c0d0e0f0)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_xmm0 = mu.reg_read(UC_X86_REG_XMM0)
        print(">>> ECX = 0x%x" % r_ecx)
        print(">>> EDX = 0x%x" % r_edx)
        print(">>> XMM0 = 0x%.32x" % r_xmm0)

        # read from memory
        tmp = mu.mem_read(ADDRESS, 4)
        print(">>> Read 4 bytes from [0x%x] = 0x" % (ADDRESS), end="")
        for i in reversed(tmp):
            print("%x" % (i), end="")
        print("")

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
