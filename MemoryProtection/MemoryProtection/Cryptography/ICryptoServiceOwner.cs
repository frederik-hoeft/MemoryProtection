using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace MemoryProtection.MemoryProtection.Cryptography
{
    internal interface ICryptoServiceOwner
    {
        private protected static readonly RNGCryptoServiceProvider RngCryptoService = new RNGCryptoServiceProvider();
    }
}
