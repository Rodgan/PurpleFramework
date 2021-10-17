using PurpleFramework.Libraries.WinApi.Core;
using PurpleFramework.Libraries.WinApi.Core.Libraries;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PurpleFramework.Libraries.ProcessInjector.Core
{

    public class ProcessInjector
    {
        public delegate void ProcessInjectorErrorEventHandler(Exception exception);
        public delegate void ProcessInjectionSuccessEventHandler();

        public event ProcessInjectorErrorEventHandler ProcessInjectorError_Event;
        public event ProcessInjectionSuccessEventHandler ProcessInjctorSuccess_Event;

        /// <summary>
        /// Inject a DLL into a process.
        /// <para>Note: the DLL must have the same architecture as the process (x86, x64)</para>
        /// </summary>
        /// <param name="processId">Process ID</param>
        /// <param name="dllPath">Path to the DLL to be injected</param>
        /// <param name="thread">If the function succeeds, the return value is a handle to the new thread.</param>
        public bool DllInjection(int processId, string dllPath, out IntPtr thread)
        {
            // https://arvanaghi.com/blog/dll-injection-using-loadlibrary-in-C/

            // How DLL Injection works:
            // - Check if DLL exists
            // - Get process handle
            // - Allocate N bytes of virtual memory (N bytes = dllPath length)
            // - Write dllPath to the allocated virtual memory
            // - Get LoadLibraryA function address [*]
            // - Make process load the DLL using CreateRemoteThread and calling LoadLibraryA
            //
            // [*]: Since LoadLibraryA is an exported function of Kernel32.dll, which is a core DLL loaded by every process, each one of them shares the same address for the function.
            // The address changes after Windows is rebooted 

            thread = IntPtr.Zero;

            try
            {
                // Check if DLL exists
                if (!File.Exists(dllPath))
                    throw new Exception("DLL not found");

                // Get process handle
                IntPtr processHandle = Kernel32.OpenProcess(WinApi.Core.PROCESS_ACCESS_RIGHT.PROCESS_ALL_ACCESS, false, processId);

                if (processHandle == IntPtr.Zero)
                    throw new WinApiException("Failed to retrieve process handle.");

                // Allocate N bytes (dllPath length) and retrieve the address of the allocated virtual memory
                IntPtr allocatedMemory = Kernel32.VirtualAllocEx(processHandle, IntPtr.Zero, dllPath.Length, WinApi.Core.MEMORY_ALLOCATION_TYPE.MEM_COMMIT | WinApi.Core.MEMORY_ALLOCATION_TYPE.MEM_RESERVE, WinApi.Core.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE);

                if (allocatedMemory == IntPtr.Zero)
                    throw new WinApiException("Failed to allocate memory.");

                // Write dllPath at the address allocatedMemory is pointing to
                bool processMemoryWritten = Kernel32.WriteProcessMemory(processHandle, allocatedMemory, Encoding.UTF8.GetBytes(dllPath), dllPath.Length, out int bytesWritten);

                if (!processMemoryWritten || bytesWritten != dllPath.Length)
                    throw new WinApiException("Failed to write process memory.");

                // Get LoadLibraryA function address
                IntPtr loadLibraryAFunctionAddress = CoreLibrary.GetFunctionAddress("Kernel32.dll", "LoadLibraryA");

                if (loadLibraryAFunctionAddress == IntPtr.Zero)
                    throw new WinApiException("Failed to retrieve LoadLibraryA function address.");

                // lpStartAddress is the address of LoadLibraryA function
                // lpParameter is the address of the allocated memory, which contains the DLL Path. This value is passed as parameter to LoadLibraryA
                thread = Kernel32.CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAFunctionAddress, allocatedMemory, THREAD_CREATION.RUN_IMMEDIATELY, out _);

                if (thread == IntPtr.Zero)
                    throw new WinApiException("Failed to create remote thread.");

                ProcessInjctorSuccess_Event?.Invoke();
                return true;
            }
            catch(Exception excp)
            {
                ProcessInjectorError_Event?.Invoke(excp);
                return false;
            }
        }

    }
}
