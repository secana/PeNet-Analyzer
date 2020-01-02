namespace PeNet.Analyzer.Anomalies
{
    public enum RuntimeBehavior
    {
        NotRunnable,
        Crash
    }

    public abstract class Anomaly
    {
        private readonly PeFile _peFile;
        public string Description { get; }
        public RuntimeBehavior RuntimeBehavior { get; }
        public bool IsMatch => MatchAnomaly(_peFile);
     

        protected Anomaly(PeFile peFile, string description, RuntimeBehavior runtimeBehavior)
            => (_peFile, Description, RuntimeBehavior) = (peFile, description, runtimeBehavior);

        protected abstract bool MatchAnomaly(PeFile peFile);
    }
}