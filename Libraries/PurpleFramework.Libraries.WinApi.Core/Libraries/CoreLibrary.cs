using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PurpleFramework.Libraries.WinApi.Core.Libraries
{
    public abstract class CoreLibrary
    {
        /// <summary>
        /// The return value is the calling thread's last-error code
        /// </summary>
        /// <returns></returns>
        [DllImport("Kernel32.dll")]
        public static extern int GetLastError();

        // https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
        /// <summary>
        /// Retrieves a module handle for the specified module. The module must have been loaded by the calling process.
        /// </summary>
        /// <param name="lpModuleName">The name of the loaded module (either a .dll or .exe file). If the file name extension is omitted, the default library extension .dll is appended. The file name string can include a trailing point character (.) to indicate that the module name has no extension. The string does not have to specify a path. When specifying a path, be sure to use backslashes (\), not forward slashes (/). The name is compared (case independently) to the names of modules currently mapped into the address space of the calling process. If this parameter is NULL, GetModuleHandle returns a handle to the file used to create the calling process (.exe file).</param>
        /// <returns>If the function succeeds, the return value is a handle to the specified module.</returns>
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetModuleHandleA(string lpModuleName);

        // https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
        /// <summary>
        /// Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
        /// </summary>
        /// <param name="hModule">A handle to the DLL module that contains the function or variable. The <see cref="GetModuleHandleA(string)"/> returns this handle.</param>
        /// <param name="lpProcName">The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.</param>
        /// <returns>If the function succeeds, the return value is the address of the exported function or variable.</returns>
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        /// <summary>
        /// (NON-NATIVE) Retrieve the address of an exported function or variable from the specified dynamic-link library (DLL). The DLL must have been loaded by the calling process.
        /// <para>This function calls <see cref="GetProcAddress(IntPtr, string)"/> and <see cref="GetModuleHandleA(string)"/></para>
        /// </summary>
        /// <param name="dllName">The name of the DLL (e.g. Kernel32.dll). If the file name extension is omitted, the default library extension .dll is appended.</param>
        /// <param name="functionName">The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.</param>
        /// <returns></returns>
        public static IntPtr GetFunctionAddress(string dllName, string functionName)
        {
            return GetProcAddress(GetModuleHandleA(dllName), functionName);
        }
    }
}
