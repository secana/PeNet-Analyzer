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


            if (!ep.Value.TryRvaToOffset(peFile.ImageSectionHeaders, out var epRaw))
                return true;

            return epRaw > peFile.FileSize;
        }
    }
}