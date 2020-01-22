namespace PeNet.Analyzer.Anomalies
{
    public class NumOfRvaAndSizesSmallerThanNumOfDataDirs : Anomaly
    {
        public NumOfRvaAndSizesSmallerThanNumOfDataDirs(PeFile peFile) 
            : base(peFile, 
                "The NumberOfRvaAndSizes is smaller than the actual number of Data Directories.", 
                RuntimeBehavior.Runnable)
        {
        }

        protected override bool MatchAnomaly(PeFile peFile)
        {
            var optHeader = peFile?.ImageNtHeaders?.OptionalHeader;
            var dd = peFile?.ImageNtHeaders?.OptionalHeader?.DataDirectory;


            if (optHeader is null || dd is null)
                return false;

            return optHeader.NumberOfRvaAndSizes < dd.Length;
        }
    }
}