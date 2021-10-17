using System;
using System.Runtime.InteropServices;

namespace PurpleFramework.Libraries.WinApi.Core.Libraries
{
    public abstract class Kernel32 : CoreLibrary
    {
        /// <summary>
        /// Creates a thread that runs in the virtual address space of another process.
        /// </summary>
        /// <param name="hProcess">>A handle to the process in which the thread is to be created. The handle must have the <see cref="PROCESS_ACCESS_RIGHT.PROCESS_CREATE_THREAD"/>, <see cref="PROCESS_ACCESS_RIGHT.PROCESS_QUERY_INFORMATION"/>, <see cref="PROCESS_ACCESS_RIGHT.PROCESS_VM_OPERATION"/>, <see cref="PROCESS_ACCESS_RIGHT.PROCESS_VM_WRITE"/> and <see cref="PROCESS_ACCESS_RIGHT.PROCESS_VM_READ"/> access rights.</param>
        /// <param name="lpThreadAttributes">A pointer to a <see cref="Structures.SECURITY_ATTTRIBUTES"/> structure specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle. If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited. The access control lists (ACL) in the default security descriptor for a thread come from the primary token of the creator.</param>
        /// <param name="dwStackSize">he initial size of the stack, in bytes. The system rounds this value to the nearest page. If this parameter is 0 (zero), the new thread uses the default size for the executable.</param>
        /// <param name="lpStartAddress">A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process. The function must exist in the remote process.</param>
        /// <param name="lpParameter">A pointer to a variable to be passed to the thread function.</param>
        /// <param name="dwCreationFlags">The flags that control the creation of the thread.</param>
        /// <param name="lpThreadId">A pointer to a variable that receives the thread identifier.</param>
        /// <returns>If the function succeeds, the return value is a handle to the new thread.</returns>
        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, THREAD_CREATION dwCreationFlags, out int lpThreadId);

        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        /// <summary>
        /// Opens an existing local process object.
        /// </summary>
        /// <param name="dwDesiredAccess">The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the <see cref="PROCESS_ACCESS_RIGHT"/>. If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.</param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
        /// <param name="dwProcessId">The identifier of the local process to be opened.</param>
        /// <returns>If the function succeeds, the return value is an open handle to the specified process. If the function fails, the return value is NULL.</returns>
        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(PROCESS_ACCESS_RIGHT dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        /// <summary>
        /// Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.
        /// </summary>
        /// <param name="hProcess">The handle to a process. The function allocates memory within the virtual address space of this process. The handle must have the <see cref="PROCESS_ACCESS_RIGHT.PROCESS_VM_OPERATION"/> access right.</param>
        /// <param name="lpAddress">The pointer that specifies a desired starting address for the region of pages that you want to allocate.</param>
        /// <param name="dwSize">The size of the region of memory to allocate, in bytes.</param>
        /// <param name="fLAllocationType">The type of memory allocation.</param>
        /// <param name="flProtect">The memory protection for the region of pages to be allocated.</param>
        /// <returns>If the function succeeds, the return value is the base address of the allocated region of pages.</returns>
        [DllImport("Kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, MEMORY_ALLOCATION_TYPE fLAllocationType, MEMORY_PROTECTION flProtect);

        // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        /// <summary>
        /// Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
        /// </summary>
        /// <param name="hProcess">A handle to the process memory to be modified. The handle must have <see cref="PROCESS_ACCESS_RIGHT.PROCESS_VM_WRITE"/> and <see cref="PROCESS_ACCESS_RIGHT.PROCESS_VM_OPERATION"/> access to the process.</param>
        /// <param name="lpBaseAddress">A pointer to the base address in the specified process to which data is written.</param>
        /// <param name="lpBuffer">A pointer to the buffer that contains data to be written in the address space of the specified process.</param>
        /// <param name="nSize">The number of bytes to be written to the specified process.</param>
        /// <param name="lpNumberOfBytesWritten">A pointer to a variable that receives the number of bytes transferred into the specified process. This parameter is optional. If <see cref="lpNumberOfBytesWritten"/> is NULL, the parameter is ignored.</param>
        /// <returns></returns>
        [DllImport("Kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
    }
}
