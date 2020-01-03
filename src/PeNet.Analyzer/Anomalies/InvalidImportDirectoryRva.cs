using System.Collections.Generic;
using PeNet.Structures;
using PeNet.Utilities;

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

            var impDirRawAddress = impDirRva.VirtualAddress.SafeRVAtoFileMapping(peFile.ImageSectionHeaders);

            return impDirRawAddress is null || impDirRawAddress > peFile.FileSize;
        }
    }
}