using MemoryProtection;
using MemoryProtection.pmdbs2X.Security.ProtectedCryptography.Sha1Protected;
using pmdbs2X.Security.MemoryProtection;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace pmdbs2X.Security.Password
{
    /// <summary>
    /// Represents a password strength checker that can be run with several analyzers.
    /// </summary>
    // TODO: Add support for ProtectedMemory
    public class PasswordAnalyzer
    {
        private readonly string password;

        /// <summary>
        /// Creates a new <see cref="PasswordAnalyzer"/> for the provided password.
        /// </summary>
        /// <param name="password">The password to be analyzed.</param>
        public PasswordAnalyzer(string password)
        {
            this.password = password;
        }

        /// <summary>
        /// The <see cref="PasswordAnalyzer"/> will run asynchronous string operations to detect commonly used patterns and bad password practices.
        /// </summary>
        /// <returns>A <see cref="Task{TResult}"/> with the <see cref="StringPatternAnalyzerResult"/> containing the result of the analysis.</returns>
        public async Task<StringPatternAnalyzerResult> RunStringPatternAnalyzerAsync() => await Task.Run(RunStringPatternAnalyzer);

        /// <summary>
        /// A <see cref="StringPatternAnalyzer"/> will run synchronous string operations to detect commonly used patterns and bad password practices.
        /// <para>May block the UIThread if it the password to check is very long.</para>
        /// </summary>
        /// <returns>A <see cref="StringPatternAnalyzerResult"/> containing the result of the analysis.</returns>
        public StringPatternAnalyzerResult RunStringPatternAnalyzer()
        {
            StringPatternAnalyzer stringPatternAnalyzer = new StringPatternAnalyzer(password);
            return stringPatternAnalyzer.Run();
        }

        /// <summary>
        /// A <see cref="PasswordLeakAnalyzer"/> will be run asynchronously against a remote database of leaked and commonly used passwords.
        /// <para>As this analyzer relies on an external API to detect leaked passwords internet access will be required.</para>
        /// </summary>
        /// <returns>A <see cref="Task{TResult}"/> with the <see cref="PasswordLeakAnalyzerResult"/> containing the result of the analysis.</returns>
        public async Task<PasswordLeakAnalyzerResult> RunPasswordLeakAnalyzerAsync()
        {
            PasswordLeakAnalyzer passwordLeakAnalyzer = new PasswordLeakAnalyzer(password);
            return await passwordLeakAnalyzer.Run();
        }

        /// <summary>
        /// All available analyzers will be run against the password.
        /// <para>Internet access will be required.</para>
        /// </summary>
        /// <returns>A <see cref="Task{TResult}"/> with the <see cref="FullAnalyzerResult"/> containing the result of the analysis.</returns>
        public async Task<FullAnalyzerResult> RunFullAnalyzerAsync()
        {
            StringPatternAnalyzer stringPatternAnalyzer = new StringPatternAnalyzer(password);
            StringPatternAnalyzerResult stringPatternAnalyzerResult = stringPatternAnalyzer.Run();
            PasswordLeakAnalyzer passwordLeakAnalyzer = new PasswordLeakAnalyzer(password);
            PasswordLeakAnalyzerResult passwordLeakAnalyzerResult = await passwordLeakAnalyzer.Run();
            return new FullAnalyzerResult(stringPatternAnalyzerResult, passwordLeakAnalyzerResult);
        }

        /// <summary>
        /// Represents an analyzer that performs string operations to detect commonly used patterns and bad password practices.
        /// </summary>
        private class StringPatternAnalyzer
        {
            private readonly string password;
            private readonly Character upperCase;
            private readonly Character lowerCase;
            private readonly NumericalCharacter number;
            private readonly SpecialCharacter symbol;
            private readonly SpecialCharacter unicode;
            private SequentialCharacter sequentialLetters;
            private SequentialCharacter sequentialNumbers;
            private SequentialCharacter sequentialSymbols;

            public StringPatternAnalyzer(string password)
            {
                this.password = password;
                upperCase = new Character(this);
                lowerCase = new Character(this);
                number = new NumericalCharacter(this);
                symbol = new SpecialCharacter(this);
                unicode = new SpecialCharacter(this);
            }

            public StringPatternAnalyzerResult Run()
            {
                SpecialCharacter.ResetMiddleSpecialCharacterCount();
                SequentialCharacter.ResetSequentialCharacterCount();
                RepeatedCharacters repeatedCharacters = new RepeatedCharacters
                {
                    Count = 0,
                    Deduction = 0
                };
                for (int index = 0; index < password.Length; index++)
                {
                    CheckCharacter(index);
                    CheckRepeatedCharacters(index, ref repeatedCharacters);
                }
                sequentialLetters = CheckSequentialLetters();
                sequentialNumbers = CheckSequentialNumbers();
                sequentialSymbols = CheckSequentialSymbols();

                int score = 0;
                ApplyPositiveMultipliers(ref score);
                ApplyNagativeMultipliers(ref score, repeatedCharacters);
                return StringPatternAnalyzerResult.FromScore(score);
            }

            private void CheckCharacter(int index)
            {
                char c = password[index];
                if (char.IsUpper(c))
                {
                    upperCase.Handle(index);
                }
                else if (char.IsLower(c))
                {
                    lowerCase.Handle(index);
                }
                else if (char.IsDigit(c))
                {
                    number.Handle(index);
                }
                else if (char.IsWhiteSpace(c) || char.IsSymbol(c))
                {
                    symbol.Handle(index);
                }
                else
                {
                    unicode.Handle(index);
                }
            }

            private void CheckRepeatedCharacters(int index, ref RepeatedCharacters repeatedCharacters)
            {
                /* Internal loop through password to check for repeat characters */
                bool repeatedCharactersExist = false;
                for (int i = 0; i < password.Length; i++)
                {
                    if (password[index] == password[i] && index != i)
                    { /* repeat character exists */
                        repeatedCharactersExist = true;
                        /*
                        Calculate increment deduction based on proximity to identical characters
                        Deduction is incremented each time a new match is discovered
                        Deduction amount is based on total password length divided by the
                        difference of distance between currently selected match
                        */
                        repeatedCharacters.Deduction += Math.Abs(password.Length / (i - index));
                    }
                }
                if (repeatedCharactersExist)
                {
                    repeatedCharacters.Count++;
                    int uniqueCharacterCount = password.Length - repeatedCharacters.Count;
                    repeatedCharacters.Deduction = (uniqueCharacterCount != 0) ? Convert.ToInt32(Math.Ceiling((double)repeatedCharacters.Deduction / uniqueCharacterCount)) : repeatedCharacters.Deduction;
                }
            }

            private SequentialCharacter CheckSequentialLetters()
            {
                const string alphabet = "abcdefghijklmnopqrstuvwxyz";
                const string keyboard = "qwertyuiopasdfghjklzxcvbnm";
                SequentialCharacter sequentialLetters = new SequentialCharacter();
                /* Check for sequential alpha string patterns (forward and reverse) */
                for (int s = 0; s < 23; s++)
                {
                    string sequence = alphabet.Substring(s, 3);
                    string reversedSequence = sequence.Reverse().ToString();
                    string keyboardSequence = keyboard.Substring(s, 3);
                    string reversedKeyboardSequence = keyboardSequence.Reverse().ToString();
                    if (password.Contains(sequence, StringComparison.OrdinalIgnoreCase) || password.Contains(reversedSequence, StringComparison.OrdinalIgnoreCase) || password.ToLower().Contains(keyboardSequence) || password.ToLower().Contains(reversedKeyboardSequence))
                    {
                        sequentialLetters.Count++;
                        sequentialLetters.SequentialCount++;
                    }
                }
                return sequentialLetters;
            }

            private SequentialCharacter CheckSequentialNumbers()
            {
                const string numbers = "01234567890";
                SequentialCharacter sequentialNumbers = new SequentialCharacter();
                /* Check for sequential numeric string patterns (forward and reverse) */
                for (int s = 0; s < numbers.Length - 2; s++)
                {
                    string sequence = numbers.Substring(s, 3);
                    string reversedSequence = sequence.Reverse().ToString();
                    if (password.Contains(sequence) || password.Contains(reversedSequence))
                    {
                        sequentialNumbers.Count++;
                        sequentialNumbers.SequentialCount++;
                    }
                }
                return sequentialNumbers;
            }

            private SequentialCharacter CheckSequentialSymbols()
            {
                const string symbols = " !\"#$%&\'()*+,-./:;<=>?@[\\]^_{|}~!\"§$%&/()=?{[]}\\,.-;:_";
                SequentialCharacter sequentialSymbols = new SequentialCharacter();
                /* Check for sequential symbol string patterns (forward and reverse) */
                for (int s = 0; s < symbols.Length - 2; s++)
                {
                    string sequence = symbols.Substring(s, 3);
                    string reversedSequence = sequence.Reverse().ToString();
                    if (password.Contains(sequence) || password.Contains(reversedSequence))
                    {
                        sequentialSymbols.Count++;
                        sequentialSymbols.SequentialCount++;
                    }
                }
                return sequentialSymbols;
            }

            private void ApplyPositiveMultipliers(ref int score)
            {
                // positive multipliers
                const int lengthMultipier = 6, numberMultiplier = 4, symbolMultiplier = 8, middleSpecialCharacterMultiplier = 2, unicodeMultiplier = 30;
                const int minimumPasswordLength = 12;
                /* Modify overall score value based on usage vs requirements */
                score += password.Length * lengthMultipier;
                if (upperCase.Count > 0 && upperCase.Count < password.Length)
                {
                    score += (password.Length - upperCase.Count) * 2;
                }
                if (lowerCase.Count > 0 && lowerCase.Count < password.Length)
                {
                    score += (password.Length - lowerCase.Count) * 2;
                }
                if (number.Count < password.Length)
                {
                    score += number.Count * numberMultiplier;
                }
                score += symbol.Count * symbolMultiplier;
                score += SpecialCharacter.GetMiddleSpecialCharacterCount() * middleSpecialCharacterMultiplier;
                score += unicode.Count * unicodeMultiplier;

                /* Determine if mandatory requirements have been met and set image indicators accordingly */
                int fulfilledRequirementsCount = password.Length >= minimumPasswordLength ? 2 : 0;
                fulfilledRequirementsCount += new int[] { upperCase.Count, lowerCase.Count, number.Count, symbol.Count }.Count(i => i > 0);

                if (fulfilledRequirementsCount > 4)
                {
                    score += fulfilledRequirementsCount * 3;
                }
            }

            private void ApplyNagativeMultipliers(ref int score, RepeatedCharacters repeatedCharacters)
            {
                // negative multipliers
                const int consecutiveUpperCaseMultiplier = 2, consecutiveLowerCaseMultiplier = 2, consecutiveNumberMultiplier = 2;
                const int sequentialLetterMultiplier = 3, sequentialNumberMultiplier = 3, sequentialSymbolMultiplier = 2;

                /* Point deductions for poor practices */
                if ((lowerCase.Count > 0 || upperCase.Count > 0) && new int[] { symbol.Count, number.Count, unicode.Count }.AllZero())
                {
                    // Only Letters
                    score -= password.Length;
                }
                if (new int[] { symbol.Count, lowerCase.Count, unicode.Count, upperCase.Count }.AllZero() && number.Count > 0)
                {
                    // Only Numbers
                    score -= password.Length;
                }
                score -= repeatedCharacters.Deduction;

                score -= upperCase.ConsecutiveCount * consecutiveUpperCaseMultiplier;
                score -= lowerCase.ConsecutiveCount * consecutiveLowerCaseMultiplier;
                score -= number.ConsecutiveCount * consecutiveNumberMultiplier;

                score -= sequentialLetters.SequentialCount * sequentialLetterMultiplier;
                score -= sequentialNumbers.SequentialCount * sequentialNumberMultiplier;
                score -= sequentialSymbols.SequentialCount * sequentialSymbolMultiplier;
                score -= SequentialCharacter.SequentialCharacterCount;
            }

            private struct RepeatedCharacters
            {
                public int Deduction;
                public int Count;
            }

            private abstract class CharacterBase
            {
                private protected int lastIndex = -1;
                public int ConsecutiveCount { get; set; } = 0;
                public int Count { get; set; } = 0;

                private protected StringPatternAnalyzer analyzer;
            }

            private class Character : CharacterBase
            {
                public Character(StringPatternAnalyzer analyzer)
                {
                    this.analyzer = analyzer;
                }

                public virtual void Handle(int index)
                {
                    if (lastIndex != 0 && (lastIndex + 1) == index)
                    {
                        ConsecutiveCount++;
                    }
                    lastIndex = index;
                    Count++;
                }
            }

            private class NumericalCharacter : Character
            {
                private protected static int MiddleSpecialCharacterCount;

                public NumericalCharacter(StringPatternAnalyzer analyzer) : base(analyzer)
                {
                }

                public override void Handle(int index)
                {
                    if (index > 0 && index < (analyzer.password.Length - 1))
                    {
                        MiddleSpecialCharacterCount++;
                    }
                    // Check if previous character was a number as well
                    base.Handle(index);
                }
            }

            private class SpecialCharacter : NumericalCharacter
            {
                public SpecialCharacter(StringPatternAnalyzer analyzer) : base(analyzer)
                {
                }

                public override void Handle(int index)
                {
                    if (index > 0 && index < (analyzer.password.Length - 1))
                    {
                        MiddleSpecialCharacterCount++;
                    }
                    Count++;
                }

                public static int GetMiddleSpecialCharacterCount()
                {
                    return MiddleSpecialCharacterCount;
                }

                public static void ResetMiddleSpecialCharacterCount()
                {
                    MiddleSpecialCharacterCount = 0;
                }
            }

            private class SequentialCharacter : CharacterBase
            {
                public static int SequentialCharacterCount;

                public int SequentialCount
                {
                    get { return SequentialCharacterCount; }
                    set { SequentialCharacterCount = value; }
                }

                public static void ResetSequentialCharacterCount()
                {
                    SequentialCharacterCount = 0;
                }
            }
        }

        /// <summary>
        /// Represents an analyzer that checks if the password has been leaked in previous data breaches and therefore is commonly being used.
        /// </summary>
        private class PasswordLeakAnalyzer
        {
            private readonly string password;

            public PasswordLeakAnalyzer(string password)
            {
                this.password = password;
            }

            public async Task<PasswordLeakAnalyzerResult> Run()
            {
                if (string.IsNullOrEmpty(password))
                {
                    return new PasswordLeakAnalyzerResult(true, -1);
                }
                Sha1ProtectedCryptoProvider sha1Provider = new Sha1ProtectedCryptoProvider();
                string result = sha1Provider.ComputeHash((IProtectedString)null).ToUpper();
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                // get a list of all the possible passwords where the first 5 digits of the hash are the same
                string url = "https://api.pwnedpasswords.com/range/" + result.Substring(0, 5);
                bool? isCompromised = null;
                int timesSeen = 0;
                WebRequest request = WebRequest.Create(url);
                using (Stream response = (await request.GetResponseAsync())?.GetResponseStream())
                using (StreamReader reader = new StreamReader(response))
                {
                    // look at each possibility and compare the rest of the hash to see if there is a match
                    string hashToCheck = result.Substring(5);
                    while (true)
                    {
                        string line = reader.ReadLine();
                        if (line == null)
                        {
                            isCompromised = false;
                            break;
                        }
                        string[] parts = line.Split(':');
                        if (parts[0].Equals(hashToCheck))
                        {
                            isCompromised = true;
                            timesSeen = Convert.ToInt32(parts[1]);
                            break;
                        }
                    }
                }
                return new PasswordLeakAnalyzerResult(isCompromised, timesSeen);
            }
        }
    }
}