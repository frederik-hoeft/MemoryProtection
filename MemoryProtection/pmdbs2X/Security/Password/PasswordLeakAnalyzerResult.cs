namespace pmdbs2X.Security.Password
{
    /// <summary>
    /// Represents the result of a password leak analysis containing information about if and how often a password has been involved in known data breaches before.
    /// </summary>
    public class PasswordLeakAnalyzerResult : AnalyzerResult
    {
        /// <summary>
        /// Indicates whether the password is compromised and should be it's usage should be avoided.
        /// </summary>
        public bool? IsCompromised { get; } = null;

        /// <summary>
        /// Specifies how often a password has been used in previous known data breaches.
        /// </summary>
        public int TimesSeen { get; } = 0;

        /// <summary>
        /// Constructs a new instance of a <see cref="PasswordLeakAnalyzerResult"/>.
        /// </summary>
        /// <param name="isCompromized">Indicates whether the password is compromised and should be it's usage should be avoided.</param>
        /// <param name="timesSeen">Specifies how often a password has been used in previous known data breaches.</param>
        public PasswordLeakAnalyzerResult(bool? isCompromized, int timesSeen) : base(!(isCompromized ?? false))
        {
            IsCompromised = isCompromized;
            TimesSeen = timesSeen;
            PasswordSecurityLevel = IsSecure ? PasswordSecurityLevel.A : PasswordSecurityLevel.F;
        }
    }
}