"""
File: x86-specific DynamoRIO model implementation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import Tuple, List
import subprocess as sbpr
import os
import numpy as np

from src.interfaces import CTrace

from ..interfaces import Input, TestCase, CTrace, InputTaint
from ..model import DRModel
from ..config import CONF
from ..util import Logger

import time

# these values must match the ones in the DR model (dr_model.c)
ENTRY_PC = 0
ENTRY_READ = 1
ENTRY_WRITE = 2
ENTRY_EOT = 3


class X86DRModel(DRModel):
    CODE_SIZE = 4096
    MAIN_REGION_SIZE = CONF.input_main_region_size
    FAULTY_REGION_SIZE = CONF.input_faulty_region_size
    OVERFLOW_REGION_SIZE = 4096

    drrun: str = "drrun"
    libdr: str = "~/.local/dr_model/libdr_model.so"
    adapter: str = "~/.local/dr_model/adapter"

    shm_buffer_short: str = "/dr_buffer"
    shm_buffer: str = "/dev/shm/dr_buffer"

    model_p: sbpr.Popen
    last_trace: List[CTrace]

    def __init__(self, sandbox_base: int, code_base: int):
        self.sandbox_base = sandbox_base
        self.code_start = code_base
        self.last_trace = [0]
        self.LOG = Logger()

        # expand paths for the DR model
        self.libdr = os.path.expanduser(self.libdr)
        self.adapter = os.path.expanduser(self.adapter)

        # check that DynamoRIO is installed and reachable
        test_cmd = [self.drrun, "-c", self.libdr, "--", "ls"]
        try:
            sbpr.run(test_cmd, check=True, stdout=sbpr.PIPE, stderr=sbpr.PIPE)
        except sbpr.CalledProcessError as e:
            print(e.stdout.decode())
            print(e.stderr.decode())
            self.LOG.error(f"Could not execute `{test_cmd}`\n       Is DynamorRIO not installed?")

        # create a shared memory for communication with the DR model
        with open(self.shm_buffer, "wb") as f:
            f.write(b'\x00')  # dummy write to create the file

        super().__init__(sandbox_base, code_base)

    def __del__(self):
        # if os.path.exists(self.shm_buffer):
        # os.remove(self.shm_buffer)
        pass

    def load_test_case(self, test_case: TestCase) -> None:
        self.test_case = test_case

    def _dr_stdout_to_trace(self, stdout: bytes, num_inputs: int) -> List[CTrace]:
        ctraces_np = np.frombuffer(stdout, dtype=np.uint64)
        if not self.LOG.dbg_model:
            assert len(stdout) == num_inputs * 8
            ctraces = list(ctraces_np)
        else:
            ctraces = self._print_dbg_and_get_traces(ctraces_np)
        self.last_trace = ctraces[-1]
        return ctraces

    def _print_dbg_and_get_traces(self, data: np.ndarray) -> List[CTrace]:
        ctraces = []
        i = 0
        input_id = 0
        sandbox_top = self.sandbox_base + self.MAIN_REGION_SIZE + self.FAULTY_REGION_SIZE \
            + self.OVERFLOW_REGION_SIZE
        sandbox_bottom = self.sandbox_base - self.OVERFLOW_REGION_SIZE

        self.LOG.dbg_model_header(input_id)
        while i < len(data):
            type_ = data[i]
            if type_ == ENTRY_PC:
                pc = int(data[i + 1])
                # size = raw_trace[i + 2] # unused
                rax = int(data[i + 3])
                rbx = int(data[i + 4])
                rcx = int(data[i + 5])
                rdx = int(data[i + 6])
                rsi = int(data[i + 7])
                rdi = int(data[i + 8])

                self.LOG.dbg_model_instruction(pc, self.test_case, False, 0)
                self.LOG.dbg_x86_formatted_reg_state(self.sandbox_base, sandbox_top, sandbox_bottom,
                                                     rax, rbx, rcx, rdx, rsi, rdi, 0, 0, 0, 0, 0, 0,
                                                     0, 0, 0)
                i += 9
                continue
            elif type_ == ENTRY_READ or type_ == ENTRY_WRITE:
                addr = int(data[i + 1])
                size = int(data[i + 2])
                # self.LOG.dbg_model_mem_access(type_ == ENTRY_READ, addr, size)
                i += 3
            elif type_ == ENTRY_EOT:
                input_id += 1
                if i < len(data) - 3:
                    self.LOG.dbg_model_header(input_id)
                ctraces.append(int(data[i + 1]),)
                i += 2
            else:
                self.LOG.error(f"Unknown dr_model trace entry type {type_}")

        return ctraces

    def trace_test_case(self, inputs: List[Input], nesting: int) -> List[CTrace]:
        now = time.time()

        # copy inputs into the model's shared memory
        with open(self.shm_buffer, "wb") as f:
            for input_ in inputs:
                f.write(input_.tobytes())
            f.flush()

        # run the DR model
        dbg = "-debug" if self.LOG.dbg_model else ""
        cmd = [
            self.drrun, '-c', self.libdr, dbg, "-tracer", CONF.contract_observation_clause, '--',
            self.adapter, self.test_case.bin_path, self.shm_buffer_short
        ]
        self.model_p = sbpr.Popen(cmd, stdout=sbpr.PIPE, stderr=sbpr.PIPE)

        # retrieve the traces from the model's stdout
        stdout, stderr = self.model_p.communicate()
        if self.model_p.returncode != 0:
            self.LOG.error(f"dr_model failed with code {self.model_p.returncode:x}\n"
                           f"STDOUT:\n {stdout!r}"
                           f"STDERR:\n {stderr.decode()}")
        # print(stdout)
        # print("received in:       ", time.time() - now)

        ctraces = self._dr_stdout_to_trace(stdout, len(inputs))
        return ctraces

    def trace_test_case_with_taints(self, inputs, nesting) -> Tuple[List[CTrace], List[InputTaint]]:
        # if CONF.inputs_per_class != 1:
        # self.LOG.error("Tainting is not yet implemented for DR model\n"
        #    "       Add `inputs_per_class: 1` to your config to disable tainting")
        taints = [InputTaint() for _ in inputs]
        for t in taints:
            t[0x2000 // 8 + 0] = 1
            t[0x2000 // 8 + 1] = 1
            t[0x2000 // 8 + 2] = 1
            t[0x2000 // 8 + 3] = 1
            t[0x2000 // 8 + 4] = 1
            t[0x2000 // 8 + 5] = 1

        return self.trace_test_case(inputs, nesting), taints

    def dbg_get_trace_detailed(self, input_, nesting, raw: bool = False) -> List[str]:
        self.trace_test_case([input_], nesting)
        return [str(self.last_trace)]


class X86DRModelGPR(X86DRModel):
    last_trace: List[int]

    def dbg_get_trace_detailed(self, input_, nesting, raw: bool = False) -> List[str]:
        self.trace_test_case([input_], nesting)
        return [str(x) for x in self.last_trace]

    def _dr_stdout_to_trace(self, stdout: bytes, num_inputs: int) -> List[CTrace]:
        ctraces_np = np.frombuffer(stdout, dtype=np.uint64)

        if "dbg_model" not in CONF.logging_modes:
            assert len(ctraces_np) == num_inputs * 6
            ctraces = []
            for i in range(num_inputs):
                ctraces.append([int(x) for x in ctraces_np[i * 6:(i + 1) * 6]])
        else:
            ctraces = self._print_dbg_and_get_traces(ctraces_np)

        self.last_trace = ctraces[-1]
        return ctraces

    def _print_dbg_and_get_traces(self, data: np.ndarray) -> List[CTrace]:
        ctraces = []
        i = 0
        input_id = 0
        sandbox_top = self.sandbox_base + self.MAIN_REGION_SIZE + self.FAULTY_REGION_SIZE \
            + self.OVERFLOW_REGION_SIZE
        sandbox_bottom = self.sandbox_base - self.OVERFLOW_REGION_SIZE

        self.LOG.dbg_model_header(input_id)
        while i < len(data):
            type_ = data[i]
            if type_ == ENTRY_PC:
                pc = int(data[i + 1])
                # size = raw_trace[i + 2] # unused
                rax = int(data[i + 3])
                rbx = int(data[i + 4])
                rcx = int(data[i + 5])
                rdx = int(data[i + 6])
                rsi = int(data[i + 7])
                rdi = int(data[i + 8])

                self.LOG.dbg_model_instruction(pc, self.test_case, False, 0)
                self.LOG.dbg_x86_formatted_reg_state(self.sandbox_base, sandbox_top, sandbox_bottom,
                                                     rax, rbx, rdx, rcx, rsi, rdi, 0, 0, 0, 0, 0, 0,
                                                     0, 0, 0)
                i += 9
                continue
            elif type_ == ENTRY_READ or type_ == ENTRY_WRITE:
                addr = int(data[i + 1])
                size = int(data[i + 2])
                # self.LOG.dbg_model_mem_access(type_ == ENTRY_READ, addr, size)
                i += 3
            elif type_ == ENTRY_EOT:
                input_id += 1
                if i < len(data) - 8:
                    self.LOG.dbg_model_header(input_id)
                ctraces.append([
                    int(data[i + 1]),
                    int(data[i + 2]),
                    int(data[i + 3]),
                    int(data[i + 4]),
                    int(data[i + 5]),
                    int(data[i + 6])
                ])
                i += 7
            else:
                self.LOG.error(f"Unknown dr_model trace entry type {type_}")

        return ctraces
