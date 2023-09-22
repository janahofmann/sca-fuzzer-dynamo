"""
File: x86-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List

# ==================================================================================================
# Allowed values of the configuration options
# ==================================================================================================
# Note: x86_option_values attribute MUST be the first attribute in the file
x86_option_values = {
    'executor': {
        'depends_on': [],
        '': [
            'x86-64-intel',
            'x86-64-amd',
        ]
    },
    'executor_mode': {
        'depends_on': [],
        '': [
            'P+P',
            'F+R',
            'E+R',
            'PP+P',
            # 'GPR' is intentionally left out
        ]
    },
    "model_backend": [
        'unicorn',
        'dynamorio',
    ],
    'permitted_faults': {
        'depends_on': ['model_backend'],
        'unicorn': [
            'DE-zero',
            'DE-overflow',
            'UD',
            'UD-vtx',
            'UD-svm',
            'PF-present',
            'PF-writable',
            'PF-smap',
            'GP-noncanonical',
            'BP',
            'BR',
            'DB-instruction',
            'assist-accessed',
            'assist-dirty',
        ],
        'dynamorio': []
    },
    'instruction_categories': {
        'depends_on': ['model_backend'],
        'unicorn': [
            # Base x86-64 - user instructions
            "BASE-BINARY",
            "BASE-BITBYTE",
            "BASE-CMOV",
            "BASE-COND_BR",
            "BASE-CONVERT",
            "BASE-DATAXFER",
            "BASE-FLAGOP",
            "BASE-LOGICAL",
            "BASE-MISC",
            "BASE-NOP",
            "BASE-POP",
            "BASE-PUSH",
            "BASE-SEMAPHORE",
            "BASE-SETCC",
            "BASE-STRINGOP",
            "BASE-WIDENOP",
            # "BASE-ROTATE",      # Unknown bug in Unicorn - emulated incorrectly
            # "BASE-SHIFT",       # Unknown bug in Unicorn - emulated incorrectly

            # Base x86 - system instructions
            "BASE-INTERRUPT",
            # "BASE-UNCOND_BR",   # Not supported: Complex control flow
            # "BASE-CALL",        # Not supported: Complex control flow
            # "BASE-RET",         # Not supported: Complex control flow
            # "BASE-SEGOP",       # Not supported: System instructions
            # "BASE-IO",          # Not supported: System instructions
            # "BASE-IOSTRINGOP",  # Not supported: System instructions
            # "BASE-SYSCALL",     # Not supported: System instructions
            # "BASE-SYSRET",      # Not supported: System instructions
            # "BASE-SYSTEM",      # Not supported: System instructions

            # Extensions
            "SSE-SSE",
            "SSE-DATAXFER",
            "SSE-MISC",
            "SSE2-DATAXFER",
            "SSE2-MISC",
            "CLFLUSHOPT-CLFLUSHOPT",
            "CLFSH-MISC",
            "SGX-SGX",
            "VTX-VTX",
            "SVM-SYSTEM",
            "MPX-MPX",
        ],
        'dynamorio': [
            # Base x86-64 - user instructions
            "BASE-BINARY",
            "BASE-BITBYTE",
            "BASE-CMOV",
            "BASE-COND_BR",
            "BASE-CONVERT",
            "BASE-DATAXFER",
            "BASE-FLAGOP",
            "BASE-LOGICAL",
            "BASE-MISC",
            "BASE-NOP",
            "BASE-POP",
            "BASE-PUSH",
            "BASE-ROTATE",
            "BASE-SEMAPHORE",
            "BASE-SETCC",
            "BASE-SHIFT",
            "BASE-STRINGOP",
            "BASE-WIDENOP",
            "LONGMODE-CONVERT",
            "LONGMODE-DATAXFER",
            "LONGMODE-POP",
            "LONGMODE-PUSH",
            "LONGMODE-SEMAPHORE",
            "LONGMODE-STRINGOP",
            # "BASE-UNCOND_BR",   # Not supported: Complex control flow
            # "BASE-CALL",        # Not supported: Complex control flow
            # "BASE-RET",         # Not supported: Complex control flow
            # "LONGMODE-RET",     # Not supported: Complex control flow

            # Base x86 - system instructions
            "BASE-INTERRUPT",
            # "BASE-SEGOP",       # Not supported: System instructions
            # "BASE-IO",          # Not supported: System instructions
            # "BASE-IOSTRINGOP",  # Not supported: System instructions
            # "BASE-SYSCALL",     # Not supported: System instructions
            # "BASE-SYSRET",      # Not supported: System instructions
            # "BASE-SYSTEM",      # Not supported: System instructions
            # "LONGMODE-SYSCALL", # Not supported: System instructions
            # "LONGMODE-SYSRET",  # Not supported: System instructions
            # "LONGMODE-SYSTEM",  # Not supported: System instructions

            # SSE
            "SSE-SSE",
            "SSE-DATAXFER",
            "SSE-MISC",
            "SSE-LOGICAL_FP",
            # "SSE-CONVERT",  # require MMX
            # "SSE-PREFETCH",  # prefetch does not trigger a mem access in unicorn
            "SSE2-SSE",
            "SSE2-DATAXFER",
            "SSE2-MISC",
            "SSE2-LOGICAL_FP",
            "SSE2-LOGICAL",
            # "SSE2-CONVERT",  # require MMX
            # "SSE2-MMX",   # require MMX
            "SSE3-SSE",
            "SSE3-DATAXFER",
            "SSE4-SSE",
            "SSE4-LOGICAL",
            "SSE4a-BITBYTE",
            "SSE4a-DATAXFER",
            # "SSSE3-MMX",  # require MMX
            "SSSE3-SSE",
            "XOP-XOP",

            # AVX
            "AVX-AVX",
            "AVX-BROADCAST",
            "AVX-CONVERT",
            "AVX-DATAXFER",
            "AVX-LOGICAL",
            "AVX-LOGICAL_FP",
            "AVX-STTNI",
            "AVX2-AVX2",
            "AVX2-BROADCAST",
            "AVX2-DATAXFER",
            "AVX2-LOGICAL",

            # Crypto
            "AES-AES",
            "AVXAES-AES",
            "GFNI-GFNI",
            "AVX_VNNI-VEX",
            "PCLMULQDQ-PCLMULQDQ",
            "RDRAND-RDRAND",
            "RDSEED-RDSEED",
            "SHA-SHA",
            "VAES-VAES",
            "VPCLMULQDQ-VPCLMULQDQ",

            # uarch features
            "CLDEMOTE-CLDEMOTE",
            "CLFLUSHOPT-CLFLUSHOPT",
            "CLFSH-MISC",
            "CLWB-CLWB",
            "CLZERO-CLZERO",
            "MCOMMIT-MISC",
            "PAUSE-MISC",
            "SERIALIZE-SERIALIZE",

            # Exceptions
            "SGX-SGX",
            "VTX-VTX",
            "SVM-SYSTEM",
            "MPX-MPX",

            # Misc
            "ADOX_ADCX-ADOX_ADCX",
            "BMI1-BMI1",
            "BMI2-BMI2",
            "LZCNT-LZCNT",
            "MOVBE-DATAXFER",
            "MOVDIR-MOVDIR",
            "RDTSCP-SYSTEM",
            "RDWRFSGS-RDWRFSGS",
            "TBM-TBM",
        ]
    },
}

# ==================================================================================================
# Instruction selection
# ==================================================================================================

# x86 executor internally uses R15, R14, RSP, RBP and, thus, they are excluded
# segment registers are also excluded as we don't support their handling so far
# same for CR* and DR*
x86_register_blocklist: List[str] = [
    # free - rax, rbx, rcx, rdx, rdi, rsi
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RSP', 'RBP',
    'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'ESP', 'EBP',
    'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W', 'SP', 'BP',
    'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'SPL', 'BPL',
    'ES', 'CS', 'SS', 'DS', 'FS', 'GS',
    'CR0', 'CR2', 'CR3', 'CR4', 'CR8',
    'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7',
    # XMM8-15 are not used when testing
    "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15",
    "YMM8", "YMM9", "YMM10", "YMM11", "YMM12", "YMM13", "YMM14", "YMM15",
]  # yapf: disable

x86_instruction_categories: List[str] = ["BASE-BINARY", "BASE-BITBYTE", "BASE-COND_BR"]
""" x86_instruction_categories: a default list of tested instruction categories """

x86_instruction_blocklist: List[str] = [
    # - STI - enables interrupts, thus corrupting the measurements; CLI - just in case
    "STI", "CLI",
    # - CPU-dependent return value
    "CPUID",
    # - Requires support of segment registers
    "XLAT", "XLATB",
    # - Requires complex instrumentation
    "ENTERW", "ENTER", "LEAVEW", "LEAVE",
    # - requires support of all possible interrupts
    "INT",
    # - system management instruction
    "ENCLS", "VMXON", "STGI", "SKINIT",
    # - non-existing instruction?
    'PCMPESTRIQ', 'PCMPESTRMQ',
    # - requires handling of MXCSR register
    "LDMXCSR", "STMXCSR", "VLDMXCSR", "VSTMXCSR",

    # - requires MMX (not supported by yet)
    "MOVQ2DQ", 'MOVDQ2Q',
]  # yapf: disable


instruction_blocklist_unicorn: List[str] = [
    # - CMPXCHG8B - Unicorn doesn't execute the mem. access hook
    #   bug: https://github.com/unicorn-engine/unicorn/issues/990
    "CMPXCHG8B", "LOCK CMPXCHG8B",
    # - Incorrect emulation
    "RCPPS", "RCPSS",

    # - under construction
    "CMPPS", "CMPSS", "COMISS", "UCOMISS", "DIVPS", "DIVSS", "MULSS", "MULPS", "MAXPS", "MAXSS",
    "MINPS", "MINSS", "RSQRTPS", "RSQRTSS", "SHUFPS", "SQRTPS", "SQRTSS", "SUBPS", "SUBSS",
    "UNPCKHPS", "UNPCKLPS", "UNPCKLP", "MOVAPS", "MOVHLPS", "MOVHPS", "MOVLHPS", "MOVLPS",
    "MOVMSKPS", "MOVNTPS", "MOVSS", "MOVUP", "MOVUPS", "MASKMOVDQU", "MOVAPD", "MOVDQ2Q", "MOVDQA",
    "MOVDQU", "MOVHPD", "MOVLPD", "MOVMSKPD", "MOVNTDQ", "MOVNTI", "MOVNTPD", "MOVQ2DQ", "MOVSD",
    "MOVUPD",
]  # yapf: disable


instruction_blocklist_dynamorio: List[str] = [
    # TEST ME:
    # "RCPPS", "RCPSS",
    # "CMPPS", "CMPSS", 'CMPPD', 'CMPSD', 'POPCNT',
    # "VPCMPESTRIQ", "VPCMPESTRMQ", "VPCMPESTRI", "VPCMPESTRM",

]

# ==================================================================================================
# x86-only options
# ==================================================================================================
x86_executor_enable_prefetcher: bool = False
""" x86_executor_enable_prefetcher: enable all prefetchers"""
x86_executor_enable_ssbp_patch: bool = True
""" x86_executor_enable_ssbp_patch: enable a patch against Speculative Store Bypass"""

x86_disable_div64: bool = True
"""
x86_disable_div64: disable 64-bit division instructions
This option is used to avoid violations cased by Zero Dividend Injection (ZDI)
"""

x86_disable_fp_simd: bool = True
"""
x86_disable_fp_simd: excludes all floating-point SIMD instructions from the test
This option is used to avoid violations cased by Floating-Point Value Injection (FPVI)
"""

fpvi_blocklist: List[str] = [
    "DIVPS", "DIVSS", 'DIVPD', 'DIVSD',
    "MULSS", "MULPS", 'MULPD', 'MULSD',
    "RSQRTPS", "RSQRTSS", "SQRTPS", "SQRTSS", 'SQRTPD', 'SQRTSD',
    'ADDPS', 'ADDSS', 'ADDPD', 'ADDSD',
    'SUBPS', 'SUBSS', 'SUBPD', 'SUBSD',
    'ADDSUBPD', 'ADDSUBPS', 'HADDPD', 'HADDPS', 'HSUBPD', 'HSUBPS',

    "VDIVPS", "VDIVSS", 'VDIVPD', 'VDIVSD',
    "VMULSS", "VMULPS", 'VMULPD', 'VMULSD',
    "VRSQRTPS", "VRSQRTSS", "VSQRTPS", "VSQRTSS", 'VSQRTPD', 'VSQRTSD',
    'VADDPS', 'VADDSS', 'VADDPD', 'VADDSD',
    'VSUBPS', 'VSUBSS', 'VSUBPD', 'VSUBSD',
    'VADDSUBPD', 'VADDSUBPS', 'VHADDPD', 'VHADDPS', 'VHSUBPD', 'VHSUBPS',

    "DPPD", "DPPS", "VDPPS", "VDPPD",
]
