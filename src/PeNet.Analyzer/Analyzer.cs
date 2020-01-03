using System.Collections.Generic;
using System.Linq;
using PeNet.Analyzer.Anomalies;

namespace PeNet.Analyzer
{
    public class Analyzer
    {
        private readonly PeFile _peFile;

        public Analyzer(PeFile peFile)
            => (_peFile) = (peFile);

        public List<IAnomaly> Anomalies
            => MatchAnomalies(_peFile);

        private List<IAnomaly> MatchAnomalies(PeFile peFile)
        {
            var anomalies = ReflectiveEnumerator.GetEnumerableOfType<Anomaly>(peFile);

            return anomalies.Where(a => a.IsMatch).ToList<IAnomaly>();
        }
    }
}