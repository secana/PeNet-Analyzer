using Xunit;

namespace PeNet.Analyzer.Test
{
    public class AnalyzerTest
    {
        [Theory]
        [InlineData(@"./Binaries/0389f753504c2aac14dd947155f2baa8cff6381ae124fcbc6cf98710271738ac", 0)]
        [InlineData(@"./Binaries/4df983666111ccfd9b4e9f5e304ae3ad9728f7d8c99ddc71bfa539eb342be13c", 2)]
        [InlineData(@"./Binaries/1daf18671e42c6550b7944360a95e65426475559a863a8140162c6bcda6728ee", 1)]
        [InlineData(@"./Binaries/3426efcbfe65a596accfd3296f74a1fc146e8afeae9c4a89cd7a452cf46ba98c", 4)]
        public void MatchAnomalies(string file, int numOfMatches)
        {
            var peFile = new PeFile(file);
            var analyzer = new Analyzer(peFile);

            Assert.Equal(numOfMatches, analyzer.Anomalies.Count);
        }
    }
}