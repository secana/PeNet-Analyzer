using PeNet.Header.Pe;

namespace PeNet.Analyzer.Anomalies
{
    public class InvalidResourceDirectory : Anomaly
    {
        public InvalidResourceDirectory(PeFile peFile) 
            : base(peFile,
                "Invalid Resource directory.", 
                RuntimeBehavior.NotRunnable) { }

        protected override bool MatchAnomaly(PeFile peFile)
        {
            bool InValidResDir(PeFile peFile)
            {
                return peFile.ImageResourceDirectory == null;
            }

            return InValidResDir(peFile)
                && peFile
                    ?.ImageNtHeaders
                    ?.OptionalHeader
                    .DataDirectory[(int)DataDirectoryType.Resource].Size != 0;
        }
    }
}