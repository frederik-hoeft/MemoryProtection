using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X.Security.MemoryProtection
{
    public interface IProtectedString : IDisposable
    {
        public int Length { get; }

        public void Append(char c);

        public bool Equals(IProtectedString other);

        public abstract char this[int index]
        {
            get;
            set;
        }

        public ProtectedMemory GetProtectedUtf8Bytes();
    }
}
