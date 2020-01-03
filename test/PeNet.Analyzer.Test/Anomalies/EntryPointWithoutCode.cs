using Xunit;

namespace PeNet.Analyzer.Test.Anomalies
{
    public class EntryPointWithoutCode
    {
        [Theory]
        [InlineData(@".\Binaries\9d5eb5ac899764d5ed30cc93df8d645e598e2cbce53ae7bb081ded2c38286d1e", false)]
        [InlineData(@".\Binaries\56eb4985aeb09e28d0a5689ba9c6f791eb6ad31143d65bdb9858e90f718eb49b", false)]
        [InlineData(@".\Binaries\0389f753504c2aac14dd947155f2baa8cff6381ae124fcbc6cf98710271738ac", false)]
        [InlineData(@".\Binaries\c1bc025393dcf0347313e56a89616314379d2eb835df81e0f00bb9b8e3821b1f", false)]
        [InlineData(@".\Binaries\8f721c7be23b762298826722bbeb4f3d74868baa881ecc5c701605e40a47e5a3", false)]
        [InlineData(@".\Binaries\bc284c90411f3ad4f0ff858fdbad164c324fe6e7b30c662363a67da0f356abeb", false)]
        [InlineData(@".\Binaries\924a92a068dd3a3cefd043fe7c59ee26c3d3582b4c140a5a14a7176019dfdb98", false)]
        [InlineData(@".\Binaries\3426efcbfe65a596accfd3296f74a1fc146e8afeae9c4a89cd7a452cf46ba98c", false)]
        [InlineData(@".\Binaries\7a8dfac680eb829cddb4af041438521babfc527cd8961521e1aeb574a863ce37", false)]
        [InlineData(@".\Binaries\6583c22f7d5ce48224875035c03643deecfcd14f29dd081021c458351b9185ea", false)]
        [InlineData(@".\Binaries\5fc887e53401a33f80dc6c5e3b8f9d7c549b9fa5a38c5b2c559b7f860c691b68", false)]
        [InlineData(@".\Binaries\1daf18671e42c6550b7944360a95e65426475559a863a8140162c6bcda6728ee", false)]
        [InlineData(@".\Binaries\0ba44e3222d1034cc2b16cc7625366777507e96ee7b988589fff9b82851c7655", true)]
        [InlineData(@".\Binaries\4df983666111ccfd9b4e9f5e304ae3ad9728f7d8c99ddc71bfa539eb342be13c", true)]
        public void HasEntryPointWithoutCode(string file, bool isValid)
        {
            var peFile = new PeFile(file);
            var anomaly = new Analyzer.Anomalies.EntryPointWithoutCode(peFile);

            Assert.Equal(isValid, anomaly.IsMatch);
        }
    }
}