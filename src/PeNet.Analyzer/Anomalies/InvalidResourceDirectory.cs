using PeNet.Header.Pe;

namespace PeNet.Analyzer.Anomalies
{
    public class InvalidResourceDirectory : Anomaly
    {
        public InvalidResourceDirectory(PeFile peFile)
            : base(peFile,
                "Invalid Resource directory.",
                RuntimeBehavior.NotRunnable)
        { }

        protected override bool MatchAnomaly(PeFile peFile)
        {

            if (peFile
                .ImageNtHeaders
                ?.OptionalHeader
                .DataDirectory[(int) DataDirectoryType.Resource].VirtualAddress == 0)
                return false;

            if (peFile.ImageResourceDirectory == null)
                return true;

            if (peFile
                .ImageNtHeaders
                ?.OptionalHeader
                .DataDirectory[(int)DataDirectoryType.Resource].Size == 0)
                return true;

            if (peFile.ImageResourceDirectory.NumberOfIdEntries +
                peFile.ImageResourceDirectory.NumberOfNameEntries > 0
                && peFile.ImageResourceDirectory.DirectoryEntries == null)
                return true;

            if (peFile.ImageResourceDirectory.NumberOfIdEntries +
                peFile.ImageResourceDirectory.NumberOfNameEntries >
                peFile.ImageResourceDirectory.DirectoryEntries?.Count)
                return true;

            return false;
        }
    }
}