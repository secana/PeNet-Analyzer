using PeNet.Analyzer.Anomalies;
using Xunit;

namespace PeNet.Analyzer.Test.Anomalies
{
    public class InvalidResourceDirectoryTest
    {
        [Theory]
        [InlineData(@"./Binaries/4d5bc8f3311079eadcc8031f5a648e7e1ec68b9d2aed0342d9ec426259603e96", false)]
        [InlineData(@"./Binaries/acfeec58dc7be53f3f35621d0cf4407273e5f61a95564461aadbabca2f3712b6", true)]
        [InlineData(@"./Binaries/1667a0ab685fc4dcceaf42bbf14407c8139842049009d23812370dae22fcb1e3", false)]
        [InlineData(@"./Binaries/4096590bacb061e8b3960140fca7a8267a91da5f3ca8ed781d00ff8e96b6c002", false)]
        [InlineData(@"./Binaries/6cf5ae6258470e82410af6b459bca25cf2d958debb937abf7b286ec98fa58f46", true)]
        [InlineData(@"./Binaries/2ba29d070c0ee0b7b795079bb0bcaff99d5a6db3ef5d82ee643157199e8f2b84", false)]
        [InlineData(@"./Binaries/d9d217f9ab7ada074f5cb6f2377fd815ca65217d6e2829e02de11479a2603432", true)]
        [InlineData(@"./Binaries/bacd60d9791230cf44773668befd752b2895438d0f8ae7b57cb950231f177d5f", true)]
        [InlineData(@"./Binaries/5f5f3fed3ce290493d0de0b4009fbdadff9ab95cc1ba552d78a81da6094557b8", false)]
        [InlineData(@"./Binaries/5d5807d417a3b07df675092754309919df0e2bcce0f1547fa63fde96d60aa1cf", false)]
        [InlineData(@"./Binaries/9443ca103b62ccc90e1a55f765477b5663742d0ccc999713f951632c573d7850", false)]
        [InlineData(@"./Binaries/9d5eb5ac899764d5ed30cc93df8d645e598e2cbce53ae7bb081ded2c38286d1e", false)]
        [InlineData(@"./Binaries/0389f753504c2aac14dd947155f2baa8cff6381ae124fcbc6cf98710271738ac", false)]
        [InlineData(@"./Binaries/c1bc025393dcf0347313e56a89616314379d2eb835df81e0f00bb9b8e3821b1f", false)]
        [InlineData(@"./Binaries/924a92a068dd3a3cefd043fe7c59ee26c3d3582b4c140a5a14a7176019dfdb98", false)]
        [InlineData(@"./Binaries/bc284c90411f3ad4f0ff858fdbad164c324fe6e7b30c662363a67da0f356abeb", false)]
        [InlineData(@"./Binaries/6583c22f7d5ce48224875035c03643deecfcd14f29dd081021c458351b9185ea", false)]
        [InlineData(@"./Binaries/5fc887e53401a33f80dc6c5e3b8f9d7c549b9fa5a38c5b2c559b7f860c691b68", false)]
        [InlineData(@"./Binaries/0ba44e3222d1034cc2b16cc7625366777507e96ee7b988589fff9b82851c7655", false)]
        [InlineData(@"./Binaries/1daf18671e42c6550b7944360a95e65426475559a863a8140162c6bcda6728ee", true)]
        [InlineData(@"./Binaries/3426efcbfe65a596accfd3296f74a1fc146e8afeae9c4a89cd7a452cf46ba98c", true)]
        [InlineData(@"./Binaries/56eb4985aeb09e28d0a5689ba9c6f791eb6ad31143d65bdb9858e90f718eb49b", true)]
        [InlineData(@"./Binaries/4df983666111ccfd9b4e9f5e304ae3ad9728f7d8c99ddc71bfa539eb342be13c", true)]
        [InlineData(@"./Binaries/8f721c7be23b762298826722bbeb4f3d74868baa881ecc5c701605e40a47e5a3", true)]
        [InlineData(@"./Binaries/7a8dfac680eb829cddb4af041438521babfc527cd8961521e1aeb574a863ce37", true)]
        public void HasInvalidResourceDirectory(string file, bool expected)
        {
            var peFile = new PeFile(file);
            var anomaly = new InvalidResourceDirectory(peFile);

            Assert.Equal(expected, anomaly.IsMatch);
        }
    }
}