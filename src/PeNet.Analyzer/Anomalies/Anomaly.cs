namespace PeNet.Analyzer.Anomalies
{
    public enum RuntimeBehavior
    {
        NotRunnable,
        Crash
    }

    public interface IAnomaly
    {
        string Description { get; }
        RuntimeBehavior RuntimeBehavior { get; }
        bool IsMatch { get; }
    }

    public abstract class Anomaly : IAnomaly
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