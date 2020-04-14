from keystone import *
from keystone.keystone_const  import *

ks_arch = dict([
    ('x86', KS_ARCH_X86),
    ('MIPS', KS_ARCH_MIPS)
])


ks_mode = dict([
    ("x16", KS_MODE_16),
    ("x32", KS_MODE_32),
    ("x64", KS_MODE_64)
])