using System;

namespace pmdbs2X.Security.Password
{
    /// <summary>
    /// Represents the result of a password pattern analysis containing information about how secure the password is against brute-force attacks with respect to common password practices.
    /// </summary>
    public sealed class StringPatternAnalyzerResult : AnalyzerResult
    {
        /// <summary>
        /// A human readable representation of the overall password complexity and therefore password strength.
        /// </summary>
        public string Complexity { get; }

        /// <summary>
        /// A simple school grade representing the password strength.
        /// </summary>
        public string Grade { get; }

        /// <summary>
        /// A score representing the overall password complexity. Higher means better.
        /// </summary>
        public int Score { get; }

        /// <summary>
        /// Constructs a new instance of a <see cref="StringPatternAnalyzerResult"/>.
        /// </summary>
        /// <param name="complexity">A human readable representation of the overall password complexity and therefore password strength.</param>
        /// <param name="grade">A simple school grade representing the password strength.</param>
        /// <param name="score">A score representing the overall password complexity. Higher means better.</param>
        private StringPatternAnalyzerResult(string complexity, string grade, int score) : base(score >= GradeToScore("C"))
        {
            Complexity = complexity;
            Grade = grade;
            Score = score;
            PasswordSecurityLevel = grade switch
            {
                _ when grade.StartsWith('A') => PasswordSecurityLevel.A,
                _ when grade.StartsWith('B') => PasswordSecurityLevel.B,
                _ when grade.StartsWith('C') => PasswordSecurityLevel.C,
                _ when grade.StartsWith('D') => PasswordSecurityLevel.D,
                _ => PasswordSecurityLevel.F
            };
        }

        /// <summary>
        /// Constructs a new instance of a <see cref="StringPatternAnalyzerResult"/> from the provided <see cref="Score"/>.
        /// </summary>
        /// <param name="score">A score representing the overall password complexity. Higher means better.</param>
        /// <returns>The <see cref="StringPatternAnalyzerResult"/> created from the score.</returns>
        public static StringPatternAnalyzerResult FromScore(int score)
        {
            /* Determine complexity and grade based on overall score */
            (string complexity, string grade) = score switch
            {
                _ when score >= 215 => ("Very Strong", "A+"),
                _ when score >= 200 => ("Very Strong", "A"),
                _ when score >= 185 => ("Strong", "A-"),
                _ when score >= 170 => ("Strong", "B+"),
                _ when score >= 155 => ("Good", "B"),
                _ when score >= 140 => ("Good", "B-"),
                _ when score >= 125 => ("Okay", "C+"),
                _ when score >= 110 => ("Okay", "C"),
                _ when score >= 95 => ("Weak", "C-"),
                _ when score >= 75 => ("Weak", "D+"),
                _ when score >= 55 => ("Very Weak", "D"),
                _ when score >= 35 => ("Very Weak", "D-"),
                _ => ("Embarrassing", "F")
            };
            return new StringPatternAnalyzerResult(complexity, grade, score);
        }

        /// <summary>
        /// Converts a provided grade to a score.
        /// </summary>
        /// <param name="grade">The grade to convert from.</param>
        /// <returns>The score representing the provided grade.</returns>
        /// <exception cref="ArgumentException"/>
        public static int GradeToScore(string grade)
        {
            return grade switch
            {
                "A+" => 215,
                "A" => 200,
                "A-" => 185,
                "B+" => 170,
                "B" => 155,
                "B-" => 140,
                "C+" => 125,
                "C" => 110,
                "C-" => 95,
                "D+" => 75,
                "D" => 55,
                "D-" => 35,
                "F" => -1,
                _ => throw new ArgumentException("Grade \'" + grade + "\' is not valid!")
            };
        }
    }
}