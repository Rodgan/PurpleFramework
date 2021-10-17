using PurpleFramework.Libraries.WinApi.Core.Libraries;
using System;
using System.Collections.Generic;
using System.Text;

namespace PurpleFramework.Libraries.WinApi.Core
{
    public class WinApiException : Exception
    {
        public WinApiException(string message) : base($"{message} System Error: 0x{CoreLibrary.GetLastError():X} ({CoreLibrary.GetLastError()})")
        {

        }
    }
}
