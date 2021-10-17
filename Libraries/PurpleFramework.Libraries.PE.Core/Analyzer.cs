using PurpleFramework.Libraries.PE.Core.Templates;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PurpleFramework.Libraries.PE.Core
{
    public class Analyzer
    {
        public delegate void AnalyzerErrorEventHandler(Exception exception);
        public delegate void AnalyzerSuccessEventHandler(PortableExecutable exe);

        public event AnalyzerErrorEventHandler AnalyzerError_Event;
        public event AnalyzerSuccessEventHandler AnalyzerSuccess_Event;

        public PortableExecutable Analyze(string path)
        {
            if (!File.Exists(path))
                return null;

            try
            {
                PortableExecutable exe = new PortableExecutable(path);

                using (var fStream = new FileStream(path, FileMode.Open))
                using (var binaryStream = new BinaryReader(fStream))
                {

                    bool msDosCompleted = false;
                    bool peSignatureCompleted = false;
                    bool fileHeaderCompleted = false;
                    bool optionalHeaderCompleted = false;
                    bool optionalHeaderWindowsSpecificCompleted = false;
                    bool optionalHeaderDataDirectoryCompleted = false;
                    bool sectionTableCompleted = false;
                    int currentSectionTable = 0;

                    long offset() { return binaryStream.BaseStream.Position; }

                    do
                    {

                        if (offset() == MSDosExe.HEADER_SIGNATURE_OFFSET)
                        {
                            exe.MSDosExe = new MSDosExe()
                            {
                                Signature = Encoding.UTF8.GetString(binaryStream.ReadBytes(MSDosExe.HEADER_SIGNATURE_SIZE))
                            };
                        }

                        if (exe.MSDosExe is MSDosExe _ms && !msDosCompleted)
                            if (offset() == MSDosExe.PE_HEADER_SIGNATURE_OFFSET) { exe.PEHeaderSignatureOffset = binaryStream.ReadUInt32(); msDosCompleted = true; }

                        if (!msDosCompleted)
                        {
                            binaryStream.ReadByte();
                            continue;
                        }

                        if (exe.PESignature is PESignature _pes && !peSignatureCompleted)
                            if (offset() == exe.PEHeaderSignatureOffset) { _pes.Signature = Encoding.UTF8.GetString(binaryStream.ReadBytes(PESignature.HEADER_SIGNATURE_SIZE)); peSignatureCompleted = true; }

                        if (!peSignatureCompleted)
                        {
                            binaryStream.ReadByte();
                            continue;
                        }

                        if (exe.FileHeader is FileHeader _fh && !fileHeaderCompleted)
                        {
                            if (offset() == exe.FileHeaderMachineOffset) { _fh.Machine = (FileHeader.MACHINE)binaryStream.ReadUInt16(); }
                            if (offset() == exe.FileHeaderNumberOfSectionsOffset) { _fh.NumberOfSections = binaryStream.ReadUInt16(); }
                            if (offset() == exe.FileHeaderTimeDateStampOffset) { _fh.TimeDateStamp = new DateTime(1970, 1, 1).ToLocalTime().AddSeconds(binaryStream.ReadUInt32()); }
                            if (offset() == exe.FileHeaderPointerToSymbolTableOffset) { _fh.PointerToSymbolTable = binaryStream.ReadUInt32(); }
                            if (offset() == exe.FileHeaderNumberOfSymbolsOffset) { _fh.NumberOfSymbols = binaryStream.ReadUInt32(); }
                            if (offset() == exe.FileHeaderSizeOfOptionalHeaderOffset) { _fh.SizeOfOptionalHeader = binaryStream.ReadUInt16(); }
                            if (offset() == exe.FileHeaderCharacteristicsOffset) { _fh.Characteristics = (FileHeader.CHARACTERISTIC)binaryStream.ReadUInt16(); fileHeaderCompleted = true; }
                        }

                        if (exe.OptionalHeader is OptionalHeader _oh && !optionalHeaderCompleted)
                        {
                            if (offset() == exe.OptionalHeaderMagicOffset) { _oh.Magic = (OptionalHeader.MAGIC)binaryStream.ReadUInt16(); }
                            if (offset() == exe.OptionalHeaderMajorLinkerVersionOffset) { _oh.MajorLinkerVersion = binaryStream.ReadByte(); }
                            if (offset() == exe.OptionalHeaderMinorLinkerVersionOffset) { _oh.MinorLinkerVersion = binaryStream.ReadByte(); }
                            if (offset() == exe.OptionalHeaderSizeOfCodeOffset) { _oh.SizeOfCode = binaryStream.ReadUInt32(); }
                            if (offset() == exe.OptionalHeaderSizeOfInitializedDataOffset) { _oh.SizeOfInitializedData = binaryStream.ReadUInt32(); }
                            if (offset() == exe.OptionalHeaderSizeOfUninitializedDataOffset) { _oh.SizeOfUninitializedData = binaryStream.ReadUInt32(); }
                            if (offset() == exe.OptionalHeaderAddressOfEntryPointOffset) { _oh.AddressOfEntryPoint = binaryStream.ReadUInt32(); }
                            if (offset() == exe.OptionalHeaderBaseOfCodeOffset) { _oh.BaseOfCode = binaryStream.ReadUInt32(); }

                            // ROM Images not supported
                            if (!optionalHeaderWindowsSpecificCompleted && (_oh.Is32BitExecutable || _oh.Is64BitOrMoreExecutable))
                            {
                                if (_oh.Is32BitExecutable)
                                {
                                    // These instructions will be read BEFORE "32-bit and 64-bit instructions 1/2"
                                    if (offset() == exe.OptionalHeaderBaseOfDataOffset) { _oh.BaseOfData = binaryStream.ReadUInt32(); }
                                    if (offset() == exe.OptionalHeaderImageBaseOffset) { _oh.ImageBase = binaryStream.ReadUInt32(); }
                                }
                                else if (_oh.Is64BitOrMoreExecutable)
                                {
                                    // These instructions will be read BEFORE "32-bit and 64-bit instructions 1/2"
                                    if (offset() == exe.OptionalHeaderImageBaseOffset) { _oh.ImageBase = binaryStream.ReadUInt64(); }
                                }

                                // 32-bit and 64-bit instructions 1/2
                                if (offset() == exe.OptionalHeaderSectionAlignmentOffset) { _oh.SectionAlignment = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderFileAlignmentOffset) { _oh.FileAlignment = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderMajorOperatingSystemVersionOffset) { _oh.MajorOperatingSystemVersion = binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderMinorOperatingSystemVersionOffset) { _oh.MinorOperatingSystemVersion = binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderMajorImageVersionOffset) { _oh.MajorImageVersion = binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderMinorImageVersionOffset) { _oh.MinorImageVersion = binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderMajorSubsystemVersionOffset) { _oh.MajorSubsystemVersion = binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderMinorSubsystemVersionOffset) { _oh.MinorSubsystemVersion = binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderWin32VersionValueOffset) { _oh.Win32VersionValue = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderSizeOfImageOffset) { _oh.SizeOfImage = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderSizeOfHeadersOffset) { _oh.SizeOfHeaders = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderCheckSumOffset) { _oh.CheckSum = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderSubsystemOffset) { _oh.Subsystem = (OptionalHeader.SUBSYSTEM)binaryStream.ReadUInt16(); }
                                if (offset() == exe.OptionalHeaderDllCharacteristicsOffset) { _oh.DllCharacteristics = (OptionalHeader.DLLCHARACTERISTIC)binaryStream.ReadUInt16(); }

                                if (_oh.Is32BitExecutable)
                                {
                                    // These instructions will be read AFTER "32-bit and 64-bit instructions 1/2" and BEFORE "32-bit and 64-bit instructions 2/2"
                                    if (offset() == exe.OptionalHeaderSizeOfStackReserveOffset) { _oh.SizeOfStackReserve = binaryStream.ReadUInt32(); }
                                    if (offset() == exe.OptionalHeaderSizeOfStackCommitOffset) { _oh.SizeOfStackCommit = binaryStream.ReadUInt32(); }
                                    if (offset() == exe.OptionalHeaderSizeOfHeapReserveOffset) { _oh.SizeOfHeapReserve = binaryStream.ReadUInt32(); }
                                    if (offset() == exe.OptionalHeaderSizeOfHeapCommitOffset) { _oh.SizeOfHeapCommit = binaryStream.ReadUInt32(); }

                                }
                                else if (_oh.Is64BitOrMoreExecutable)
                                {
                                    // These instructions will be read AFTER "32-bit and 64-bit instructions 1/2" and BEFORE "32-bit and 64-bit instructions 2/2"
                                    if (offset() == exe.OptionalHeaderSizeOfStackReserveOffset) { _oh.SizeOfStackReserve = binaryStream.ReadUInt64(); }
                                    if (offset() == exe.OptionalHeaderSizeOfStackCommitOffset) { _oh.SizeOfStackCommit = binaryStream.ReadUInt64(); }
                                    if (offset() == exe.OptionalHeaderSizeOfHeapReserveOffset) { _oh.SizeOfHeapReserve = binaryStream.ReadUInt64(); }
                                    if (offset() == exe.OptionalHeaderSizeOfHeapCommitOffset) { _oh.SizeOfHeapCommit = binaryStream.ReadUInt64(); }
                                }

                                // 32-bit and 64-bit instructions 2/2
                                if (offset() == exe.OptionalHeaderLoaderFlagsOffset) { _oh.LoaderFlags = binaryStream.ReadUInt32(); }
                                if (offset() == exe.OptionalHeaderNumberOfRvaAndSizes) { _oh.NumberOfRelativeVirtualAddressesAndSizes = binaryStream.ReadUInt32(); optionalHeaderWindowsSpecificCompleted = true; } // Last option header window-specific field
                            }

                            // ROM Images not supported
                            if (!optionalHeaderDataDirectoryCompleted && (_oh.Is32BitExecutable || _oh.Is64BitOrMoreExecutable))
                            {
                                if (_oh.HasExportTable && offset() == exe.OptionalHeaderExportTableOffset) { _oh.ExportTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasImportTable && offset() == exe.OptionalHeaderImportTableOffset) { _oh.ImportTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasResourceTable && offset() == exe.OptionalHeaderResourceTableOffset) { _oh.ResourceTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasExceptionTable && offset() == exe.OptionalHeaderExceptionTableOffset) { _oh.ExceptionTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasCertificateTable && offset() == exe.OptionalHeaderCertificateTableOffset) { _oh.CertificateTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasBaseRelocationTable && offset() == exe.OptionalHeaderBaseRelocationTableOffset) { _oh.BaseRelocationTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasDebug && offset() == exe.OptionalHeaderDebugOffset) { _oh.Debug = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasArchitecture && offset() == exe.OptionalHeaderArchitectureOffset) { _oh.Architecture = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasGlobalPtr && offset() == exe.OptionalHeaderGlobalPtrOffset) { _oh.GlobalPtr = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasThreadLocalStorageTable && offset() == exe.OptionalHeaderThreadLocalStorageTableOffset) { _oh.ThreadLocalStorageTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasLoadConfigTable && offset() == exe.OptionalHeaderLoadConfigTableOffset) { _oh.LoadConfigTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasBoundImport && offset() == exe.OptionalHeaderBoundImportOffset) { _oh.BoundImport = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasImportAddressTable && offset() == exe.OptionalHeaderImportAddressTableOffset) { _oh.ImportAddressTable = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasDelayImportDescriptor && offset() == exe.OptionalHeaderDelayImportDescriptorOffset) { _oh.DelayImportDescriptor = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasCLRRuntimeHeader && offset() == exe.OptionalHeaderCLRRuntimeHeaderOffset) { _oh.CLRRuntimeHeader = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); }
                                if (_oh.HasReservedDataDirectory && offset() == exe.OptionalHeaderReservedDataDirectoryOffset) { _oh.ReservedDataDirectory = new OptionalHeader.IMAGE_DATA_DIRECTORY(binaryStream); optionalHeaderCompleted = true; }
                            }
                        }

                        if (exe.SectionTables is List<SectionTable> _sh && !sectionTableCompleted)
                        {
                            if (offset() != exe.SectionTableBaseOffset) throw new InvalidOperationException($"Section Headers base offset is 0x{exe.SectionTableBaseOffset:X} but should be 0x{offset():X}");

                            // Create section header
                            while (currentSectionTable < exe.FileHeader.NumberOfSections)
                            {
                                var sectionHeader = new SectionTable(exe.OptionalHeader.SectionAlignment, exe.OptionalHeader.FileAlignment);

                                if (offset() == exe.SectionTableNameOffset + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.Name = Encoding.UTF8.GetString(binaryStream.ReadBytes(8)); }
                                if (offset() == exe.SectionTableVirtualSizeOffset + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.VirtualSize = binaryStream.ReadUInt32(); }
                                if (offset() == exe.SectionTableVirtualAddressOffset + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.VirtualAddress = binaryStream.ReadUInt32(); }
                                if (offset() == exe.SectionTableSizeOfRawDataOffset + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.SizeOfRawData = binaryStream.ReadUInt32(); }
                                if (offset() == exe.SectionTablePointerToRawData + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.PointerToRawData = binaryStream.ReadUInt32(); }
                                if (offset() == exe.SectionTablePointerToRelocations + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.PointerToRelocations = binaryStream.ReadUInt32(); }
                                if (offset() == exe.SectionTablePointerToLineNumbers + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.PointerToLineNumbers = binaryStream.ReadUInt32(); }
                                if (offset() == exe.SectionTableNumberOfRelocations + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.NumberOfRelocations = binaryStream.ReadUInt16(); }
                                if (offset() == exe.SectionTableNumberOfLineNumbers + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.NumberOfLineNumbers = binaryStream.ReadUInt16(); }
                                if (offset() == exe.SectionTableCharacteristics + (SectionTable.SECTION_TABLE_SIZE * currentSectionTable)) { sectionHeader.Characteristics = (SectionTable.CHARACTERISTIC)binaryStream.ReadUInt32(); }

                                _sh.Add(sectionHeader);
                                currentSectionTable++;
                            }

                            // Get section data
                            currentSectionTable = 0;
                            while (currentSectionTable < exe.FileHeader.NumberOfSections)
                            {
                                if (_sh.FirstOrDefault(x => offset() == x.PointerToRawData) is SectionTable _st)
                                {
                                    _st.RawData = new byte[_st.SizeOfRawData];
                                    _st.RawData = binaryStream.ReadBytes((int)_st.SizeOfRawData);
                                    currentSectionTable++;
                                }
                                else
                                {
                                    binaryStream.ReadByte();
                                    continue;
                                }
                            }

                            // Associate known tables with headers
                            exe.OptionalHeader.ExportTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.ImportTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.ResourceTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.ExceptionTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.CertificateTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.BaseRelocationTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.Debug?.SetSectionTable(_sh);
                            exe.OptionalHeader.Architecture?.SetSectionTable(_sh);
                            exe.OptionalHeader.GlobalPtr?.SetSectionTable(_sh);
                            exe.OptionalHeader.ThreadLocalStorageTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.LoadConfigTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.BoundImport?.SetSectionTable(_sh);
                            exe.OptionalHeader.ImportAddressTable?.SetSectionTable(_sh);
                            exe.OptionalHeader.DelayImportDescriptor?.SetSectionTable(_sh);
                            exe.OptionalHeader.CLRRuntimeHeader?.SetSectionTable(_sh);
                            exe.OptionalHeader.ReservedDataDirectory?.SetSectionTable(_sh);

                            sectionTableCompleted = true;
                        }

                        if (msDosCompleted && peSignatureCompleted && fileHeaderCompleted && optionalHeaderCompleted && sectionTableCompleted)
                            break;

                        binaryStream.ReadByte();

                    }
                    while (true);

                }

                AnalyzerSuccess_Event?.Invoke(exe);

                return exe;
            }
            catch (Exception excp)
            {
                AnalyzerError_Event?.Invoke(excp);

                return null;
            }
        }
    }
}
