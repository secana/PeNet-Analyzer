using PeNet.Utilities;

namespace PeNet.Analyzer.Anomalies
{
    public class EntryPointWithoutCode : Anomaly
    {
        public EntryPointWithoutCode(PeFile peFile) 
            : base(peFile,
                "No code found at the entry point of the executable.",
                RuntimeBehavior.Crash) { }

        protected override bool MatchAnomaly(PeFile peFile)
        {
            if (peFile.HasEntryPointOutOfFileSize())
                return false;

            var ep = peFile.ImageNtHeaders?.OptionalHeader?.AddressOfEntryPoint;

            if (ep is null)
                return true;
            if (ep == 0) return false;

            var epRaw = ep.Value.SafeRVAtoFileMapping(peFile.ImageSectionHeaders);

            if (epRaw is null)
                return true;

            if (epRaw + 4 > peFile.FileSize)
                return false;

            return peFile.Buff[epRaw.Value] == 0
                   && peFile.Buff[epRaw.Value + 1] == 0
                   && peFile.Buff[epRaw.Value + 2] == 0
                   && peFile.Buff[epRaw.Value + 3] == 0;
        }
    }
}