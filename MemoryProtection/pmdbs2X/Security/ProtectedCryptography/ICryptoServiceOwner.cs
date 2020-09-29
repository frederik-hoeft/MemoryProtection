using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace pmdbs2X.Security.ProtectedCryptography
{
    internal interface ICryptoServiceOwner
    {
        private protected static readonly RNGCryptoServiceProvider RngCryptoService = new RNGCryptoServiceProvider();
    }
}
