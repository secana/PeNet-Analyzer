using System.Collections.Generic;
using System.Linq;
using MoreLinq.Extensions;
using PeNet.Structures;
using PeNet.Utilities;

namespace PeNet.Analyzer
{
    public static class Analyzer
    {
        public static bool IsInvalid(this PeFile peFile) =>
            peFile.HasEntryPointOutOfFileSize()
            || peFile.HasInvalidImportDirectoryRva()
            || peFile.HasInvalidSection()
            || peFile.HasEntryPointWithoutCode()
            || peFile.HasInvalidResourceDirectory();

        public static bool HasEntryPointOutOfFileSize(this PeFile peFile)
        {
            var ep = peFile.ImageNtHeaders?.OptionalHeader?.AddressOfEntryPoint;

            if (ep is null)
                return true;
            if (ep == 0) return false;

            //var epRaw = peFile.RvaToPhysicalAddress(ep.Value);
            var epRaw = ep.Value.SafeRVAtoFileMapping(peFile.ImageSectionHeaders);

            if (epRaw is null)
                return true;

            return epRaw > peFile.FileSize;
        }

        public static bool HasEntryPointWithoutCode(this PeFile peFile)
        {
            if (peFile.HasEntryPointOutOfFileSize())
                return false;

            var ep = peFile.ImageNtHeaders?.OptionalHeader?.AddressOfEntryPoint;

            if (ep is null)
                return true;
            if (ep == 0) return false;

            var epRaw = peFile.RvaToPhysicalAddress(ep.Value);

            if (epRaw is null)
                return true;

            if (epRaw + 4 > peFile.FileSize)
                return false;

            return peFile.Buff[epRaw.Value] == 0
                   && peFile.Buff[epRaw.Value + 1] == 0
                   && peFile.Buff[epRaw.Value + 2] == 0
                   && peFile.Buff[epRaw.Value + 3] == 0;
        }

        public static bool HasInvalidImportDirectoryRva(this PeFile peFile)
        {
            bool HasImportDir(IReadOnlyCollection<IMAGE_DATA_DIRECTORY> dataDir)
                => !(dataDir?.Count < (int)Constants.DataDirectoryIndex.Import + 1);

            var dataDirectory = peFile.ImageNtHeaders?.OptionalHeader?.DataDirectory;

            if (dataDirectory == null) return true;
            if (!HasImportDir(dataDirectory)) return true;

            var impDirRva = dataDirectory[(int)Constants.DataDirectoryIndex.Import];

            if (impDirRva is null)
                return true;

            if (impDirRva.VirtualAddress == 0
                && impDirRva.Size == 0)
                return false;

            var impDirRawAddress = peFile.RvaToPhysicalAddress(impDirRva.VirtualAddress);

            return impDirRawAddress is null || impDirRawAddress > peFile.FileSize;
        }

        public static bool HasInvalidSection(this PeFile peFile)
        {
            var maxSection = peFile.ImageSectionHeaders.
                MaxBy(s => s.SizeOfRawData + s.PointerToRawData)
                .First();

            if (maxSection is null)
                return true;

            return maxSection.SizeOfRawData + maxSection.PointerToRawData > peFile.FileSize;
        }

        public static bool HasInvalidResourceDirectory(this PeFile peFile)
            => !peFile.HasValidResourceDir
               && peFile.ImageNtHeaders.OptionalHeader.DataDirectory[(int)Constants.DataDirectoryIndex.Resource].Size != 0;

        private static uint? RvaToPhysicalAddress(this PeFile peFile, uint rva)
        {
            IMAGE_SECTION_HEADER? GetSectionForRva(uint rva)
            {
                var sectionsByRva = peFile.ImageSectionHeaders.OrderBy(s => s.VirtualAddress).ToList();
                return sectionsByRva.FirstOrDefault(t =>
                    rva >= t.VirtualAddress && rva < t.VirtualAddress + t.VirtualSize);
            }

            var section = GetSectionForRva(rva);

            if (section is null)
                return null;

            return rva - section.VirtualAddress + section.PointerToRawData;
        }
    }
}
