using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection.ProtectedString
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

        public new ProtectedStringNode Next { get; set; }

        public new ProtectedStringNode Previous { get; set; }

        public new char Value
        {
            get
            {
                byte[] bytes = base.Value.Read(0, 2);
                ushort value = bytes[1];
                return (char)(value + (ushort)(bytes[0] << 8));
            }
            set
            {
                byte[] bytes = new byte[2];
                bytes[1] = (byte)value;
                bytes[0] = (byte)(value >> 8);
                base.Value.Write(bytes, 0);
            }
        }

        public bool Equals(ProtectedStringNode other)
        {
            return Value == other.Value;
        }
    }
}
