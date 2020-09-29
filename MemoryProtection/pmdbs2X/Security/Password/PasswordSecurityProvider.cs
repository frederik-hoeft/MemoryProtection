using System;
using System.Threading.Tasks;

namespace pmdbs2X.Security.Password
{
    /// <summary>
    /// Provides a static interface for the <see cref="Password"/> name space.
    /// </summary>
    public static class PasswordSecurityProvider
    {
        /// <summary>
        /// Evaluates the strength of the provided password.
        /// </summary>
        /// <param name="password">The password to evaluate.</param>
        /// <returns>A <see cref="Tuple{T1,T2}"/> containing the <see cref="PasswordSecurityLevel"/> and the strength represented by a percentage where higher means stronger against brute-force attacks.</returns>
        public static async Task<(PasswordSecurityLevel, double)> Evaluator(string password)
        {
            PasswordAnalyzer analyzer = new PasswordAnalyzer(password);
            StringPatternAnalyzerResult result = await analyzer.RunStringPatternAnalyzerAsync();
            const double minScore = 34d;
            const double maxScore = 215d;
            double percentage;
            if (result.Score <= minScore)
            {
                percentage = 0d;
            }
            else if (result.Score >= maxScore)
            {
                percentage = 1d;
            }
            else
            {
                percentage = (result.Score - minScore) / (maxScore - minScore);
            }
            return (result.PasswordSecurityLevel, percentage);
        }
    }
}