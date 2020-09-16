using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.MemoryProtection
{
    public interface IProtectedString : IDisposable
    {
        public int Length { get; }

        public void Append(char c);

        public bool Equals(IProtectedString other);

        public ProtectedMemory GetProtectedUtf8Bytes();
    }
}
