namespace pmdbs2X.Security.Password
{
    /// <summary>
    /// Represents a generic result of any <see cref="PasswordAnalyzer"/>.
    /// <para>Cannot be instantiated and acts as a base class for other analyzer results.</para>
    /// </summary>
    public abstract class AnalyzerResult
    {
        /// <summary>
        /// Indicates whether the analyzed password is considered to be "secure enough" to be used.
        /// </summary>
        public bool IsSecure { get; private protected set; }

        /// <summary>
        /// Represents the <see cref="PasswordSecurityLevel"/> of the analyzed password to easily classify it's strength.
        /// </summary>
        public PasswordSecurityLevel PasswordSecurityLevel { get; private protected set; }

        private protected AnalyzerResult()
        {
        }

        private protected AnalyzerResult(bool isSecure)
        {
            IsSecure = isSecure;
        }
    }

    /// <summary>
    /// Represents the security level of a password using a simple grading system.
    /// </summary>
    public enum PasswordSecurityLevel
    {
        /// <summary>
        /// The lowest security level for the most insecure passwords.
        /// </summary>
        F,

        /// <summary>
        /// The second lowest security level for pretty bad passwords.
        /// </summary>
        D,

        /// <summary>
        /// An intermediate security level for acceptable passwords.
        /// </summary>
        C,

        /// <summary>
        /// The second highest security level for good passwords.
        /// </summary>
        B,

        /// <summary>
        /// The highest security level for the best passwords.
        /// </summary>
        A
    }
}