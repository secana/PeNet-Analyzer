using System.Linq;

namespace PeNet.Analyzer.Anomalies
{
    public class SectionOutOfBounds : Anomaly
    {
        public SectionOutOfBounds(PeFile peFile)
            : base(peFile,
                "One or more sections are outside of the executable.",
                RuntimeBehavior.NotRunnable) { }

        protected override bool MatchAnomaly(PeFile peFile)
        {
            var maxSection = peFile.ImageSectionHeaders.
                OrderByDescending(s => s.SizeOfRawData + s.PointerToRawData)
                .First();

            if (maxSection is null)
                return true;

            return maxSection.SizeOfRawData + maxSection.PointerToRawData > peFile.FileSize;
        }
    }
}