using System;
using System.Collections.Generic;
using System.Text;

namespace pmdbs2X
{
    internal static class Extensions
    {
        internal static bool AllZero(this int[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                if (arr[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
