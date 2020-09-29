using System;

namespace pmdbs2X.Security.Password
{
    /// <summary>
    /// Represents the full summery of all available <see cref="AnalyzerResult"/>s.
    /// </summary>
    public sealed class FullAnalyzerResult : AnalyzerResult
    {
        /// <summary>
        /// The <see cref="StringPatternAnalyzerResult"/> for the password.
        /// </summary>
        public StringPatternAnalyzerResult StringPatternAnalyzerResult { get; }

        /// <summary>
        /// The <see cref="PasswordLeakAnalyzerResult"/> for the password.
        /// </summary>
        public PasswordLeakAnalyzerResult PasswordLeakAnalyzerResult { get; }

        /// <summary>
        /// Constructs a new <see cref="FullAnalyzerResult"/> object from existing <seealso cref="AnalyzerResult"/> objects.
        /// </summary>
        /// <param name="stringPatternAnalyzerResult">The <see cref="StringPatternAnalyzerResult"/> for the password.</param>
        /// <param name="passwordLeakAnalyzerResult">The <see cref="PasswordLeakAnalyzerResult"/> for the password.</param>
        public FullAnalyzerResult(StringPatternAnalyzerResult stringPatternAnalyzerResult, PasswordLeakAnalyzerResult passwordLeakAnalyzerResult) : base(stringPatternAnalyzerResult.IsSecure && passwordLeakAnalyzerResult.IsSecure)
        {
            StringPatternAnalyzerResult = stringPatternAnalyzerResult;
            PasswordLeakAnalyzerResult = passwordLeakAnalyzerResult;
            PasswordSecurityLevel = (PasswordSecurityLevel)Math.Min((byte)stringPatternAnalyzerResult.PasswordSecurityLevel, (byte)passwordLeakAnalyzerResult.PasswordSecurityLevel);
        }
    }
}