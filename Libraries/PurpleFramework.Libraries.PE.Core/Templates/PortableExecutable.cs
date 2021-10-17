using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PurpleFramework.Libraries.PE.Core.Templates
{
    public class PortableExecutable
    {
        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only
        #region PE Signature
        public uint PEHeaderSignatureOffset { get; set; }
        #endregion

        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
        #region File Header Offsets
        public uint FileHeaderBaseOffset => PEHeaderSignatureOffset + PESignature.HEADER_SIGNATURE_SIZE;
        public uint FileHeaderMachineOffset => FileHeaderBaseOffset + 0;
        public uint FileHeaderNumberOfSectionsOffset => FileHeaderBaseOffset + 2;
        public uint FileHeaderTimeDateStampOffset => FileHeaderBaseOffset + 4;
        public uint FileHeaderPointerToSymbolTableOffset => FileHeaderBaseOffset + 8;
        public uint FileHeaderNumberOfSymbolsOffset => FileHeaderBaseOffset + 12;
        public uint FileHeaderSizeOfOptionalHeaderOffset => FileHeaderBaseOffset + 16;
        public uint FileHeaderCharacteristicsOffset => FileHeaderBaseOffset + 18;
        #endregion

        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
        #region Optional Header
        public uint OptionalHeaderBaseOffset => OptionalHeader is null ? 0 : FileHeaderCharacteristicsOffset + FileHeader.FILE_HEADER_CHARACTERISTICS_SIZE;
        public uint OptionalHeaderMagicOffset => OptionalHeaderBaseOffset + 0;
        public uint OptionalHeaderMajorLinkerVersionOffset => OptionalHeaderBaseOffset + 2;
        public uint OptionalHeaderMinorLinkerVersionOffset => OptionalHeaderBaseOffset + 3;
        public uint OptionalHeaderSizeOfCodeOffset => OptionalHeaderBaseOffset + 4;
        public uint OptionalHeaderSizeOfInitializedDataOffset => OptionalHeaderBaseOffset + 8;
        public uint OptionalHeaderSizeOfUninitializedDataOffset => OptionalHeaderBaseOffset + 12;
        public uint OptionalHeaderAddressOfEntryPointOffset => OptionalHeaderBaseOffset + 16;
        public uint OptionalHeaderBaseOfCodeOffset => OptionalHeaderBaseOffset + 20;
        public uint OptionalHeaderBaseOfDataOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            0 :
            OptionalHeaderBaseOffset + 24; // 32-bit only 

        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
        #region Optional Header Windows-Specific Offsets
        public uint OptionalHeaderImageBaseOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 24 : // 64-bit or more
            OptionalHeaderBaseOffset + 28; // 32-bit
        public uint OptionalHeaderSectionAlignmentOffset => OptionalHeaderBaseOffset + 32;
        public uint OptionalHeaderFileAlignmentOffset => OptionalHeaderBaseOffset + 36;
        public uint OptionalHeaderMajorOperatingSystemVersionOffset => OptionalHeaderBaseOffset + 40;
        public uint OptionalHeaderMinorOperatingSystemVersionOffset => OptionalHeaderBaseOffset + 42;
        public uint OptionalHeaderMajorImageVersionOffset => OptionalHeaderBaseOffset + 44;
        public uint OptionalHeaderMinorImageVersionOffset => OptionalHeaderBaseOffset + 46;
        public uint OptionalHeaderMajorSubsystemVersionOffset => OptionalHeaderBaseOffset + 48;
        public uint OptionalHeaderMinorSubsystemVersionOffset => OptionalHeaderBaseOffset + 50;
        public uint OptionalHeaderWin32VersionValueOffset => OptionalHeaderBaseOffset + 52;
        public uint OptionalHeaderSizeOfImageOffset => OptionalHeaderBaseOffset + 56;
        public uint OptionalHeaderSizeOfHeadersOffset => OptionalHeaderBaseOffset + 60;
        public uint OptionalHeaderCheckSumOffset => OptionalHeaderBaseOffset + 64;
        public uint OptionalHeaderSubsystemOffset => OptionalHeaderBaseOffset + 68;
        public uint OptionalHeaderDllCharacteristicsOffset => OptionalHeaderBaseOffset + 70;
        public uint OptionalHeaderSizeOfStackReserveOffset => OptionalHeaderBaseOffset + 72;
        public uint OptionalHeaderSizeOfStackCommitOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 80 : // 64-bit or more
            OptionalHeaderBaseOffset + 76; // 32-bit
        public uint OptionalHeaderSizeOfHeapReserveOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 88 : // 64-bit or more
            OptionalHeaderBaseOffset + 80; // 32-bit
        public uint OptionalHeaderSizeOfHeapCommitOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 96 : // 64-bit or more
            OptionalHeaderBaseOffset + 84; // 32-bit
        public uint OptionalHeaderLoaderFlagsOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 104 : // 64-bit or more
            OptionalHeaderBaseOffset + 88; // 32-bit
        public uint OptionalHeaderNumberOfRvaAndSizes =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 108 : // 64-bit or more
            OptionalHeaderBaseOffset + 92; // 32-bit
        #endregion

        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
        #region Optional Header Data Directory
        public uint OptionalHeaderExportTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 112 : // 64-bit or more
            OptionalHeaderBaseOffset + 96; // 32-bit
        public uint OptionalHeaderImportTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 120 : // 64-bit or more
            OptionalHeaderBaseOffset + 104; // 32-bit
        public uint OptionalHeaderResourceTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 128 : // 64-bit or more
            OptionalHeaderBaseOffset + 112; // 32-bit
        public uint OptionalHeaderExceptionTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 136 : // 64-bit or more
            OptionalHeaderBaseOffset + 120; // 32-bit
        public uint OptionalHeaderCertificateTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 144 : // 64-bit or more
            OptionalHeaderBaseOffset + 128; // 32-bit
        public uint OptionalHeaderBaseRelocationTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 152 : // 64-bit or more
            OptionalHeaderBaseOffset + 136; // 32-bit
        public uint OptionalHeaderDebugOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 160 : // 64-bit or more
            OptionalHeaderBaseOffset + 144; // 32-bit
        public uint OptionalHeaderArchitectureOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 168 : // 64-bit or more
            OptionalHeaderBaseOffset + 152; // 32-bit
        public uint OptionalHeaderGlobalPtrOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 176 : // 64-bit or more
            OptionalHeaderBaseOffset + 160; // 32-bit
        public uint OptionalHeaderThreadLocalStorageTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 184 : // 64-bit or more
            OptionalHeaderBaseOffset + 168; // 32-bit
        public uint OptionalHeaderLoadConfigTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 192 : // 64-bit or more
            OptionalHeaderBaseOffset + 176; // 32-bit
        public uint OptionalHeaderBoundImportOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 200 : // 64-bit or more
            OptionalHeaderBaseOffset + 184; // 32-bit
        public uint OptionalHeaderImportAddressTableOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 208 : // 64-bit or more
            OptionalHeaderBaseOffset + 192; // 32-bit
        public uint OptionalHeaderDelayImportDescriptorOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 216 : // 64-bit or more
            OptionalHeaderBaseOffset + 200; // 32-bit
        public uint OptionalHeaderCLRRuntimeHeaderOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 224 : // 64-bit or more
            OptionalHeaderBaseOffset + 208; // 32-bit
        public uint OptionalHeaderReservedDataDirectoryOffset =>
            OptionalHeader is OptionalHeader _opt && _opt.Is64BitOrMoreExecutable ?
            OptionalHeaderBaseOffset + 232 : // 64-bit or more
            OptionalHeaderBaseOffset + 216; // 32-bit
        #endregion

        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
        #region Section Table (Section Headers)
        private readonly string path;

        public uint SectionTableBaseOffset => OptionalHeaderBaseOffset + (FileHeader?.SizeOfOptionalHeader ?? 0);
        public uint SectionTableNameOffset => SectionTableBaseOffset + 0;
        public uint SectionTableVirtualSizeOffset => SectionTableBaseOffset + 8;
        public uint SectionTableVirtualAddressOffset => SectionTableBaseOffset + 12;
        public uint SectionTableSizeOfRawDataOffset => SectionTableBaseOffset + 16;
        public uint SectionTablePointerToRawData => SectionTableBaseOffset + 20;
        public uint SectionTablePointerToRelocations => SectionTableBaseOffset + 24;
        public uint SectionTablePointerToLineNumbers => SectionTableBaseOffset + 28;
        public uint SectionTableNumberOfRelocations => SectionTableBaseOffset + 32;
        public uint SectionTableNumberOfLineNumbers => SectionTableBaseOffset + 34;
        public uint SectionTableCharacteristics => SectionTableBaseOffset + 36;
        #endregion
        #endregion

        public MSDosExe MSDosExe { get; set; }
        public PESignature PESignature
        {
            get
            {
                if (MSDosExe is MSDosExe _ms && _ms.Signature.StartsWith("MZ"))
                {
                    if (_peSignature is null)
                        _peSignature = new PESignature();
                }

                return _peSignature;
            }
        }
        private PESignature _peSignature;
        public FileHeader FileHeader
        {
            get
            {
                if (PESignature is PESignature _pe && _pe.Signature.StartsWith("PE"))
                {
                    if (_fileHeader is null)
                        _fileHeader = new FileHeader();
                }

                return _fileHeader;
            }
        }
        private FileHeader _fileHeader = null;

        public OptionalHeader OptionalHeader
        {
            get
            {
                if ((FileHeader?.SizeOfOptionalHeader ?? 0) > 0)
                {
                    if (_optionalHeader is null)
                        _optionalHeader = new OptionalHeader();
                }

                return _optionalHeader;
            }
        }
        private OptionalHeader _optionalHeader = null;

        public List<SectionTable> SectionTables
        {
            get
            {
                if ((FileHeader?.NumberOfSections ?? 0) > 0)
                {
                    if (_sectionTables is null)
                        _sectionTables = new List<SectionTable>();
                }

                return _sectionTables;
            }
        }
        public List<SectionTable> _sectionTables;

        #region Injector
        public bool CanAddSection
        {
            get
            {
                return SectionTableBaseOffset + (((FileHeader?.NumberOfSections ?? 0) + 1) * SectionTable.SECTION_TABLE_SIZE) < FirstSectionPointerToRawData;
            }
        }
        public uint NewSectionTableOffset
        {
            get
            {
                return SectionTableBaseOffset + ((FileHeader?.NumberOfSections ?? 0) * SectionTable.SECTION_TABLE_SIZE);
            }
        }
        public uint NewSectionVirtualAddress
        {
            get
            {
                if ((SectionTables?.Count ?? 0) > 0)
                    return SectionTables.Last().NextVirtualAddress;

                return OptionalHeader?.SectionAlignment ?? 0;
            }
        }
        public uint NewSectionPointerToRawData
        {
            get
            {
                if ((SectionTables?.Count ?? 0) > 0)
                    return SectionTables.Last().NextPointerToRawData;

                return FirstSectionPointerToRawData;
            }
        }

        public uint FirstSectionPointerToRawData
        {
            get
            {
                // The actual end of optional header offset is OptionalHeaderBaseOffset + FileHeader.SizeOfOptionalHeader.
                // We need SECTION_TABLE_SIZE because we need the header in order to have a section.
                var endOfOptionalHeaderOffset = OptionalHeaderBaseOffset + (FileHeader?.SizeOfOptionalHeader ?? 0) + SectionTable.SECTION_TABLE_SIZE;

                // The section must be aligned to FileAlignment
                var offsets = (endOfOptionalHeaderOffset / (OptionalHeader?.FileAlignment ?? 1));
                var addOffset = endOfOptionalHeaderOffset % (OptionalHeader?.FileAlignment ?? 0) > 0 ? (uint)1 : 0;

                return (OptionalHeader?.FileAlignment ?? 0) * (offsets + addOffset);
            }
        }
        public List<InjectableCode> InjectableCodes
        {
            get
            {
                if (_injectableCodes is null)
                    _injectableCodes = new List<InjectableCode>();

                return _injectableCodes;
            }
            set
            {
                _injectableCodes = value;
            }
        }
        private List<InjectableCode> _injectableCodes;

        /// <summary>
        /// Create a new section header 
        /// </summary>
        /// <param name="name"></param>
        /// <param name="rawData"></param>
        /// <param name="characteristics"></param>
        /// <returns></returns>
        public bool CreateSection(string name, byte[] rawData, SectionTable.CHARACTERISTIC characteristics)
        {
            if (!CanAddSection)
                return false;

            if (FileHeader is null)
                return false;

            if (OptionalHeader is null)
                return false;

            // Create new section
            var newSection = new SectionTable(name, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, NewSectionVirtualAddress, NewSectionPointerToRawData, rawData, characteristics);
            var sectionTableInjectableCode = new InjectableCode(NewSectionTableOffset, newSection.GetSectionTableAsByteArray()); // This section must be created BEFORE adding 1 to NumberOfSections

            // Update the number of sections
            SectionTables.Add(newSection);
            FileHeader.NumberOfSections++;

            var sectionRawDataInjectableCode = new InjectableCode(newSection.PointerToRawData, newSection.RawData);

            // Update the size of image once loaded in memory (VirtualAddress of last section + VirtualSize of last section)
            var sizeInMemory = (SectionTables?.Last().VirtualSize ?? 0) + (SectionTables?.Last().VirtualAddress ?? 0);
            OptionalHeader.SizeOfImage = sizeInMemory;

            // Create injectable code
            AddInjectableCodeAtAddress(OptionalHeaderSizeOfImageOffset, BitConverter.GetBytes(OptionalHeader.SizeOfImage));
            AddInjectableCodeAtAddress(FileHeaderNumberOfSectionsOffset, BitConverter.GetBytes(FileHeader.NumberOfSections));
            AddInjectableCodeAtAddress(sectionTableInjectableCode);
            AddInjectableCodeAtAddress(sectionRawDataInjectableCode);

            return true;
        }
        /// <summary>
        /// Inject the code in the disk raw data image and save the result in <paramref name="savePath"/>
        /// </summary>
        /// <param name="savePath"></param>
        public void InjectCodeInDiskImageAndSaveTo(string savePath)
        {
            if (InjectableCodes.Count == 0)
                return;

            using (var fStream = new FileStream(path, FileMode.Open))
            using (var binaryReader = new BinaryReader(fStream))
            {
                // Calculate the new file size based on the file length + the length of new code to be injected
                var sizeOnDisk = InjectableCodes.Where(x => x.Address >= binaryReader.BaseStream.Length).Sum(x => x.Size) + binaryReader.BaseStream.Length;
                var buffer = new byte[sizeOnDisk];

                using (var memStream = new MemoryStream(buffer))
                using (var binaryWriter = new BinaryWriter(memStream))
                {
                    long offset() => binaryWriter.BaseStream.Position;

                    while (offset() < buffer.Length)
                    {
                        if (InjectableCodes.FirstOrDefault(x => x.Address == (uint)offset()) is InjectableCode _ic)
                        {
                            if (binaryReader.BaseStream.Position < binaryReader.BaseStream.Length - _ic.Size - 1)
                                binaryReader.ReadBytes((int)_ic.Size);

                            binaryWriter.Write(_ic.Data);
                        }
                        else
                        {
                            byte nextByte = binaryReader.BaseStream.Position < binaryReader.BaseStream.Length - 1 ? binaryReader.ReadByte() : (byte)0x0;
                            binaryWriter.Write(nextByte);
                        }
                    }

                    binaryReader.Close();
                    fStream.Close();

                    File.WriteAllBytes(savePath, buffer);
                }
            }
        }

        void AddInjectableCodeAtAddress(InjectableCode injectableCode) => AddInjectableCodeAtAddress(injectableCode.Address, injectableCode.Data);
        void AddInjectableCodeAtAddress(uint address, byte[] data)
        {
            if (InjectableCodes.FirstOrDefault(x => x.Address == address) is InjectableCode _existingInjectableCode)
            {
                _existingInjectableCode.Data = data;
                return;
            }

            InjectableCodes.Add(new InjectableCode(address, data));
        }
        #endregion

        public PortableExecutable(string path)
        {
            this.path = path;
        }
    }
}
