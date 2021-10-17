using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PurpleFramework.Libraries.PE.Core.Templates
{
    public class OptionalHeader
    {
        public class IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress { get; set; }
            public uint Size { get; set; }
            public SectionTable SectionHeader { get; set; }

            public IMAGE_DATA_DIRECTORY(BinaryReader binaryStream)
            {
                VirtualAddress = binaryStream.ReadUInt32();
                Size = binaryStream.ReadUInt32();
            }

            public void SetSectionTable(List<SectionTable> sectionTables)
            {
                foreach (var sectionTable in sectionTables)
                {
                    if (VirtualAddress >= sectionTable.VirtualAddress && VirtualAddress < sectionTable.NextVirtualAddress)
                    {
                        SectionHeader = sectionTable;
                        return;
                    }
                }
            }
        }
        public enum MAGIC : ushort
        {
            UNKNOWN = 0X0,
            PORTABLE_EXECUTABLE_32_BIT = 0x10b,
            ROM_IMAGE = 0x107,
            PORTABLE_EXECUTABLE_64_BIT_OR_MORE = 0x20b
        }
        public enum SUBSYSTEM : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_OS2_CUI = 5,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
        }
        [Flags]
        public enum DLLCHARACTERISTIC : ushort
        {
            RESERVED_01 = 0x0001,
            RESERVED_02 = 0x0002,
            RESERVED_03 = 0x0004,
            RESERVED_04 = 0x0008,
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
        }


        public bool Is32BitExecutable => Magic == MAGIC.PORTABLE_EXECUTABLE_32_BIT;
        public bool Is64BitOrMoreExecutable => Magic == MAGIC.PORTABLE_EXECUTABLE_64_BIT_OR_MORE;
        public bool IsROMImage => Magic == MAGIC.ROM_IMAGE;

        public MAGIC Magic { get; set; }
        public byte MajorLinkerVersion { get; set; }
        public byte MinorLinkerVersion { get; set; }
        public uint SizeOfCode { get; set; }
        public uint SizeOfInitializedData { get; set; }
        public uint SizeOfUninitializedData { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public uint BaseOfCode { get; set; }
        public uint BaseOfData { get; set; } // 32-bit only

        #region Windows-Specific Fields (PE32 / PE32+)
        public ulong ImageBase { get; set; }
        public uint SectionAlignment { get; set; }
        public uint FileAlignment { get; set; }
        public ushort MajorOperatingSystemVersion { get; set; }
        public ushort MinorOperatingSystemVersion { get; set; }
        public ushort MajorImageVersion { get; set; }
        public ushort MinorImageVersion { get; set; }
        public ushort MajorSubsystemVersion { get; set; }
        public ushort MinorSubsystemVersion { get; set; }
        public uint Win32VersionValue { get; set; }
        public uint SizeOfImage { get; set; }
        public uint SizeOfHeaders { get; set; }
        public uint CheckSum { get; set; }
        public SUBSYSTEM Subsystem { get; set; }
        public DLLCHARACTERISTIC DllCharacteristics { get; set; }
        public ulong SizeOfStackReserve { get; set; }
        public ulong SizeOfStackCommit { get; set; }
        public ulong SizeOfHeapReserve { get; set; }
        public ulong SizeOfHeapCommit { get; set; }
        public uint LoaderFlags { get; set; }
        public uint NumberOfRelativeVirtualAddressesAndSizes { get; set; }
        #endregion

        #region Data Directories
        public bool HasExportTable => NumberOfRelativeVirtualAddressesAndSizes >= 1;
        public bool HasImportTable => NumberOfRelativeVirtualAddressesAndSizes >= 2;
        public bool HasResourceTable => NumberOfRelativeVirtualAddressesAndSizes >= 3;
        public bool HasExceptionTable => NumberOfRelativeVirtualAddressesAndSizes >= 4;
        public bool HasCertificateTable => NumberOfRelativeVirtualAddressesAndSizes >= 5;
        public bool HasBaseRelocationTable => NumberOfRelativeVirtualAddressesAndSizes >= 6;
        public bool HasDebug => NumberOfRelativeVirtualAddressesAndSizes >= 7;
        public bool HasArchitecture => NumberOfRelativeVirtualAddressesAndSizes >= 8;
        public bool HasGlobalPtr => NumberOfRelativeVirtualAddressesAndSizes >= 9;
        public bool HasThreadLocalStorageTable => NumberOfRelativeVirtualAddressesAndSizes >= 10;
        public bool HasLoadConfigTable => NumberOfRelativeVirtualAddressesAndSizes >= 11;
        public bool HasBoundImport => NumberOfRelativeVirtualAddressesAndSizes >= 12;
        public bool HasImportAddressTable => NumberOfRelativeVirtualAddressesAndSizes >= 13;
        public bool HasDelayImportDescriptor => NumberOfRelativeVirtualAddressesAndSizes >= 14;
        public bool HasCLRRuntimeHeader => NumberOfRelativeVirtualAddressesAndSizes >= 15;
        public bool HasReservedDataDirectory => NumberOfRelativeVirtualAddressesAndSizes == 16;

        public IMAGE_DATA_DIRECTORY ExportTable { get; set; }
        public IMAGE_DATA_DIRECTORY ImportTable { get; set; }
        public IMAGE_DATA_DIRECTORY ResourceTable { get; set; }
        public IMAGE_DATA_DIRECTORY ExceptionTable { get; set; }
        public IMAGE_DATA_DIRECTORY CertificateTable { get; set; }
        public IMAGE_DATA_DIRECTORY BaseRelocationTable { get; set; }
        public IMAGE_DATA_DIRECTORY Debug { get; set; }
        public IMAGE_DATA_DIRECTORY Architecture { get; set; }
        public IMAGE_DATA_DIRECTORY GlobalPtr { get; set; }
        public IMAGE_DATA_DIRECTORY ThreadLocalStorageTable { get; set; }
        public IMAGE_DATA_DIRECTORY LoadConfigTable { get; set; }
        public IMAGE_DATA_DIRECTORY BoundImport { get; set; }
        public IMAGE_DATA_DIRECTORY ImportAddressTable { get; set; }
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor { get; set; }
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader { get; set; }
        public IMAGE_DATA_DIRECTORY ReservedDataDirectory { get; set; }

        #endregion
    }
}
