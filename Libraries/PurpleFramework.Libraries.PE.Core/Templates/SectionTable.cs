using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PurpleFramework.Libraries.PE.Core.Templates
{
    public class SectionTable
    {
        public const uint SECTION_TABLE_SIZE = 40; // each section table is 40 bytes long
        private readonly uint sectionAlignment;
        private readonly uint fileAlignment;

        [Flags]
        public enum CHARACTERISTIC : uint
        {
            RESERVED_00 = 0x00000000,
            RESERVED_01 = 0x00000001,
            RESERVED_02 = 0x00000002,
            RESERVED_03 = 0x00000004,
            IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
            RESERVED_04 = 0x00000010,
            IMAGE_SCN_CNT_CODE = 0x00000020,
            IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
            IMAGE_SCN_LNK_OTHER = 0x00000100,
            IMAGE_SCN_LNK_INFO = 0x00000200,
            RESERVED_05 = 0x00000400,
            IMAGE_SCN_LNK_REMOVE = 0x00000800,
            IMAGE_SCN_LNK_COMDAT = 0x00001000,
            IMAGE_SCN_GPREL = 0x00008000,
            IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
            IMAGE_SCN_MEM_16BIT = 0x00020000,
            IMAGE_SCN_MEM_LOCKED = 0x00040000,
            IMAGE_SCN_MEM_PRELOAD = 0x00080000,
            IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
            IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
            IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
            IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
            IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
            IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
            IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
            IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
            IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
            IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
            IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
            IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
            IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
            IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
            IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
            IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
            IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
            IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
            IMAGE_SCN_MEM_SHARED = 0x10000000,
            IMAGE_SCN_MEM_EXECUTE = 0x20000000,
            IMAGE_SCN_MEM_READ = 0x40000000,
            IMAGE_SCN_MEM_WRITE = 0x80000000
        }
        private string _name;
        public string Name
        {
            get => _name;
            set
            {
                if ((value?.Length ?? 0) > 8)
                    _name = value.Substring(0, 8);

                _name = value.PadRight(8, (char)0);
            }
        }
        public uint VirtualSize { get; set; }
        public uint VirtualAddress { get; set; }
        public uint NextVirtualAddress
        {
            get
            {
                var mod = ((VirtualSize + VirtualAddress) % sectionAlignment) > 0 ? 1 : (uint)0;

                return sectionAlignment * (((VirtualSize + VirtualAddress) / sectionAlignment) + mod);
            }
        }
        public uint SizeOfRawData { get; set; }
        public uint PointerToRawData { get; set; }
        public uint NextPointerToRawData
        {
            get
            {
                var mod = ((SizeOfRawData + PointerToRawData) % fileAlignment) > 0 ? 1 : (uint)0;

                return fileAlignment * (((SizeOfRawData + PointerToRawData) / fileAlignment) + mod);
            }
        }
        public byte[] RawData { get; set; }
        public uint PointerToRelocations { get; set; }
        public uint PointerToLineNumbers { get; set; }
        public ushort NumberOfRelocations { get; set; }
        public ushort NumberOfLineNumbers { get; set; }
        public CHARACTERISTIC Characteristics { get; set; }


        public SectionTable(uint sectionAlignment, uint fileAlignment)
        {
            this.sectionAlignment = sectionAlignment;
            this.fileAlignment = fileAlignment;
        }

        public SectionTable(string name, uint sectionAlignment, uint fileAlignment, uint virtualAddress, uint pointerToRawData, byte[] rawData, CHARACTERISTIC characteristics)
        {
            Name = name;
            VirtualAddress = virtualAddress;
            PointerToRawData = pointerToRawData;
            Characteristics = characteristics;
            this.sectionAlignment = sectionAlignment;
            this.fileAlignment = fileAlignment;

            var rawDataSize = (uint)(rawData?.Length ?? 0);

            VirtualSize = sectionAlignment * ((rawDataSize / sectionAlignment) + 1);
            SizeOfRawData = fileAlignment * ((rawDataSize / fileAlignment) + 1);
            RawData = new byte[SizeOfRawData];

            Array.Copy(rawData, RawData, rawDataSize);
        }

        public byte[] GetSectionTableAsByteArray()
        {
            var data = new byte[SECTION_TABLE_SIZE];

            using (var memStream = new MemoryStream(data))
            using (var binaryWriter = new BinaryWriter(memStream))
            {
                // If we do not use GetBytes() for Name, binaryWriter will write 9 characters instead of 8
                // because the first character of a string is the length of the string itself
                binaryWriter.Write(Encoding.UTF8.GetBytes(Name));
                binaryWriter.Write(VirtualSize);
                binaryWriter.Write(VirtualAddress);
                binaryWriter.Write(SizeOfRawData);
                binaryWriter.Write(PointerToRawData);
                binaryWriter.Write(PointerToRelocations);
                binaryWriter.Write(PointerToLineNumbers);
                binaryWriter.Write(NumberOfRelocations);
                binaryWriter.Write(NumberOfLineNumbers);
                binaryWriter.Write((uint)Characteristics);
            }

            return data;
        }
    }
}
