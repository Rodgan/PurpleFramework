using System;
using System.Collections.Generic;
using System.Text;

namespace PurpleFramework.Libraries.PE.Core.Templates
{
    public class InjectableCode
    {
        public uint Address { get; private set; }
        public uint Size
        {
            get { return (uint)(Data?.Length ?? 0); }
        }
        public byte[] Data { get; set; }

        public InjectableCode(uint address, byte[] data)
        {
            Address = address;
            Data = data;
        }
    }
}
