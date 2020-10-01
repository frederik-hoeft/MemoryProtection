using pmdbs2X.Security.MemoryProtection;
using pmdbs2X.Security.Password;
using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.Password
{
    public class ProtectedPasswordAnalyzer
    {
        private readonly IProtectedString password;
        public ProtectedPasswordAnalyzer(IProtectedString password)
        {
            this.password = password;
        }

        public StringPatternAnalyzerResult RunStringPatternAnalyzer()
        {
            StringPatternAnalyzer stringPatternAnalyzer = new StringPatternAnalyzer(password);
            return stringPatternAnalyzer.Run();
        }

        private class StringPatternAnalyzer
        {
            private readonly IProtectedString password;
            private readonly Character upperCase;
            private readonly Character lowerCase;
            private readonly NumericalCharacter number;
            private readonly SpecialCharacter symbol;
            private readonly SpecialCharacter unicode;
            private SequentialCharacter sequentialLetters;
            private SequentialCharacter sequentialNumbers;
            private SequentialCharacter sequentialSymbols;
            public StringPatternAnalyzer(IProtectedString password)
            {
                this.password = password;
                upperCase = new Character(this);
                lowerCase = new Character(this);
                number = new NumericalCharacter(this);
                symbol = new SpecialCharacter(this);
                unicode = new SpecialCharacter(this);
            }

            internal StringPatternAnalyzerResult Run()
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
                throw new NotImplementedException();
            }

            private void CheckRepeatedCharacters(int index, ref RepeatedCharacters repeatedCharacters)
            {
                throw new NotImplementedException();
            }

            private void CheckCharacter(int index)
            {
                throw new NotImplementedException();
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
    }
}
