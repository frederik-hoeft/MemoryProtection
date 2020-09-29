using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection.ProtectedString
{
    internal sealed class ProtectedStringNode : ProtectedListNode
    {
        public ProtectedStringNode() : base(sizeof(char))
        {
        }

        public ProtectedStringNode(char c) : base(sizeof(char))
        {
            Value = c;
        }

        public int SequenceLength { get; private set; }

        public new ProtectedStringNode Next { get; set; }

        public new ProtectedStringNode Previous { get; set; }

        public new char Value
        {
            get
            {
                byte[] bytes = base.Value.Read(0, 4);
                Rune.DecodeFromUtf8(bytes, out Rune result, out _);
                return (char)result.Value;
            }
            set
            {
                Rune rune = new Rune(value);
                byte[] bytes = new byte[4];
                rune.EncodeToUtf8(bytes);
                SequenceLength = rune.Utf8SequenceLength;
                base.Value.Write(bytes, 0);
            }
        }

        public ProtectedMemory GetProtectedMemory()
        {
            return base.Value;
        }

        public bool Equals(ProtectedStringNode other)
        {
            return Value == other.Value;
        }
    }
}
