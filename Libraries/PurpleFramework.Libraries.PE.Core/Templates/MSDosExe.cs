using System;
using System.Collections.Generic;
using System.Text;

namespace PurpleFramework.Libraries.PE.Core.Templates
{
    public class MSDosExe
    {
        public const int HEADER_SIGNATURE_OFFSET = 0x0;
        public const int HEADER_SIGNATURE_SIZE = 2;
        public const int PE_HEADER_SIGNATURE_OFFSET = 0x3C;
        public string Signature { get; set; }
    }
}
