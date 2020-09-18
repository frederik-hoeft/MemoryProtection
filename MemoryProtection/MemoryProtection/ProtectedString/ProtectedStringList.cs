using MemoryProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryProtection.MemoryProtection.ProtectedString
{
    // This is a linked list with each character being of type ProtectedMemory.
    // During comparison only a single character will be unprotected.
    public class ProtectedStringList : IProtectedString
    {
        private int rawContentLength;
        public int Length { get; private set; }
        private ProtectedStringNode head;
        private ProtectedStringNode tail;

        public void Append(char c)
        {
            ProtectedStringNode node = new ProtectedStringNode(c);
            rawContentLength += node.SequenceLength;
            if (Length == 0)
            {
                head = node;
                tail = node;
            }
            else if (Length == 1)
            {
                tail = node;
                head.Next = node;
                node.Previous = head;
            }
            else
            {
                tail.Next = node;
                node.Previous = tail;
                tail = node;
            }
            Length++;
        }

        public override bool Equals(object obj)
        {
            return Equals((ProtectedStringList)obj);
        }

        public bool Equals(ProtectedStringList other)
        {
            if (Length != other.Length)
            {
                return false;
            }
            ProtectedStringNode node = head;
            ProtectedStringNode otherNode = other.head;
            while (node != null && otherNode != null)
            {
                if (node.Value != otherNode.Value)
                {
                    return false;
                }
                node = node.Next;
                otherNode = otherNode.Next;
            }
            return true;
        }

        public void Dispose()
        {
            ProtectedStringNode node = head;
            while (node != null)
            {
                ProtectedStringNode toFree = node;
                node = node.Next;
                toFree.Dispose();
            }
        }

        public bool Equals(IProtectedString other)
        {
            if (GetType() != other.GetType())
            {
                return false;
            }
            return Equals((ProtectedStringList)other);
        }

        public unsafe ProtectedMemory GetProtectedUtf8Bytes()
        {
            ProtectedMemory result = ProtectedMemory.Allocate(rawContentLength);
            using (ProtectedMemoryAccess resultAccess = new ProtectedMemoryAccess(result))
            {
                byte* memory = (byte*)resultAccess.Handle;
                ProtectedStringNode node = head;
                int offset = 0;
                for (int i = 0; i < Length; i++)
                {
                    ProtectedMemory protectedNodeMemory = node.GetProtectedMemory();
                    using (ProtectedMemoryAccess access = new ProtectedMemoryAccess(protectedNodeMemory))
                    {
                        byte* nodeMemory = (byte*)access.Handle;
                        for (int j = 0; j < 4; j++)
                        {
                            if (nodeMemory[j] == 0x0)
                            {
                                break;
                            }
                            memory[offset] = nodeMemory[j];
                            offset++;
                        }
                    }
                    node = node.Next;
                }
            }
            return result;
        }
    }
}
