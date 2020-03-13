
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
            if (new EntryPointOutOfBounds(peFile).IsMatch)
                return false;

            var ep = peFile.ImageNtHeaders?.OptionalHeader?.AddressOfEntryPoint;

            if (ep is null)
                return true;
            if (ep == 0) return false;

            if (!ep.Value.TryRvaToOffset(peFile.ImageSectionHeaders, out var epRaw))
                return true;

            if (epRaw + 4 > peFile.FileSize)
                return false;

            var s = peFile.RawFile.AsSpan(epRaw, 4);
            return s[0] == 0
                   && s[1] == 0
                   && s[2] == 0
                   && s[3] == 0;
        }
    }
}