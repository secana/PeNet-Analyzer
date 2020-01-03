namespace PeNet.Analyzer.Anomalies
{
    public class InvalidResourceDirectory : Anomaly
    {
        public InvalidResourceDirectory(PeFile peFile) 
            : base(peFile,
                "Invalid Resource directory.", 
                RuntimeBehavior.NotRunnable) { }

        protected override bool MatchAnomaly(PeFile peFile)
            => !peFile.HasValidResourceDir
               && peFile
                   .ImageNtHeaders
                   .OptionalHeader
                   .DataDirectory[(int)Constants.DataDirectoryIndex.Resource].Size != 0;
    }
}