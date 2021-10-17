using System;
using System.Collections.Generic;
using System.Text;

namespace PurpleFramework.Libraries.WinApi.Core
{
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    [Flags]
    public enum MEMORY_ALLOCATION_TYPE : int
    {
        MEM_COMMIT = 0x00001000,
        MEM_RESERVE = 0x00002000,
        MEM_RESET = 0x00080000,
        MEM_RESET_UNDO = 0x1000000,
        MEM_LARGE_PAGES = 0x20000000,
        MEM_PHYSICAL = 0x00400000,
        MEM_TOP_DOWN = 0x00100000
    }

    // https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    [Flags]
    public enum MEMORY_PROTECTION : int
    {
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_TARGETS_INVALID = 0x40000000,
        PAGE_TARGETS_NO_UPDATE = 0x40000000,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400
    }

    // https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    [Flags]
    public enum PROCESS_ACCESS_RIGHT : long
    {
        DELETE = 0x00010000L,
        READ_CONTROL = 0x00020000L,
        SYNCHRONIZE = 0x00100000L,
        WRITE_DAC = 0x00040000L,
        WRITE_OWNER = 0x00080000L,

        PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_TERMINATE = 0x0001,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0020,
        PROCESS_VM_WRITE = 0x0020,

        PROCESS_ALL_ACCESS = (0x000F0000L | 0x00100000L | 0xFFF)
    }

    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    [Flags]
    public enum THREAD_CREATION : int
    {
        RUN_IMMEDIATELY = 0,
        CREATE_SUSPENDED = 0x00000004,
        STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
    }
}
