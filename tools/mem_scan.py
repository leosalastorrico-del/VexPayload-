"""Scan a live process for a marker string (dormant-memory proof).

Usage: python tools/mem_scan.py <pid> <marker> [--wait SECONDS]
Exit 0 always; prints the hit count so the caller can assert it.
"""

import ctypes
import ctypes.wintypes as wt
import sys
import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def scan(pid, marker):
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wt.HANDLE
    k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                   ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                   ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = wt.BOOL
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
    hits = 0
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    buf = ctypes.create_string_buffer(1 << 20)
    try:
        while addr < 0x7FFFFFFFFFFF:
            if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            if size == 0:
                break
            if (mbi.State == MEM_COMMIT
                    and not (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))):
                done = 0
                while done < size:
                    chunk = min(size - done, 1 << 20)
                    read = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(base + done),
                                             buf, chunk, ctypes.byref(read)):
                        hits += buf.raw[:read.value].count(marker)
                    done += chunk
            addr = base + size
    finally:
        k32.CloseHandle(h)
    return hits


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: mem_scan.py <pid> <marker> [--wait S]")
        sys.exit(2)
    pid, marker = int(sys.argv[1]), sys.argv[2].encode()
    wait = 0.0
    if "--wait" in sys.argv:
        wait = float(sys.argv[sys.argv.index("--wait") + 1])
    time.sleep(wait)
    print(scan(pid, marker))
