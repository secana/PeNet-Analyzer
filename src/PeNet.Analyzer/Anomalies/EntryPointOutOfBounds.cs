using PeNet.Utilities;

namespace PeNet.Analyzer.Anomalies
{
    public class EntryPointOutOfBounds : Anomaly
    {
        public EntryPointOutOfBounds(PeFile peFile) 
            : base(peFile, 
                "The executables entry point is outside of the executable.", 
                RuntimeBehavior.NotRunnable) { }

        protected override bool MatchAnomaly(PeFile peFile)
        {
            var ep = peFile.ImageNtHeaders?.OptionalHeader?.AddressOfEntryPoint;

            if (ep is null)
                return true;
            if (ep == 0) return false;

            var epRaw = ep.Value.SafeRVAtoFileMapping(peFile.ImageSectionHeaders);

            if (epRaw is null)
                return true;

            return epRaw > peFile.FileSize;
        }
    }
}