using PeNet.Analyzer.Anomalies;
using Xunit;

namespace PeNet.Analyzer.Test.Anomalies
{
    public class NumOfRvaAndSizesSmallerThanNumOfDataDirsTest
    {
        [Theory]
        [InlineData(@".\Binaries\78e859b5bc8d9adf4635a12f405710a0b9710e09278bc1453ca6dd5413aeff1c", true)]
        [InlineData(@".\Binaries\0ba44e3222d1034cc2b16cc7625366777507e96ee7b988589fff9b82851c7655", false)]
        [InlineData(@".\Binaries\1daf18671e42c6550b7944360a95e65426475559a863a8140162c6bcda6728ee", false)]
        public void NumberOfRvaAndSizesSmallerThanNumOfDataDirs(string file, bool isValid)
        {
            var peFile = new PeFile(file);
            var anomaly = new NumOfRvaAndSizesSmallerThanNumOfDataDirs(peFile);

            Assert.Equal(isValid, anomaly.IsMatch);
        }
    }
}