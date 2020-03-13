using System.Collections.Generic;
using PeNet.Header.Pe;

namespace PeNet.Analyzer.Anomalies
{
    public class InvalidImportDirectoryRva : Anomaly
    {
        public InvalidImportDirectoryRva(PeFile peFile) 
            : base(peFile, 
                "Import directory relative virtual address is invalid.",
                RuntimeBehavior.NotRunnable) { }

        protected override bool MatchAnomaly(PeFile peFile)
        {
            bool HasImportDir(IReadOnlyCollection<ImageDataDirectory> dataDir)
                => !(dataDir?.Count < (int)DataDirectoryType.Import + 1);

            var dataDirectory = peFile.ImageNtHeaders?.OptionalHeader?.DataDirectory;

            if (dataDirectory == null) return true;
            if (!HasImportDir(dataDirectory)) return true;

            var impDirRva = dataDirectory[(int)DataDirectoryType.Import];

            if (impDirRva.VirtualAddress == 0
                && impDirRva.Size == 0)
                return false;

            return !impDirRva.VirtualAddress.TryRvaToOffset(peFile.ImageSectionHeaders, out var impDirRawAddress) 
                   || impDirRawAddress > peFile.FileSize;
        }
    }
}