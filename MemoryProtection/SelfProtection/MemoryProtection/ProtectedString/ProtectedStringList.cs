using MemoryProtection.SelfProtection.MemoryProtection;
using System;
using System.Collections.Generic;
using System.Text;

namespace MemoryProtection.SelfProtection.MemoryProtection.ProtectedString
{
    // This is a linked list with each character being of type ProtectedMemory.
    // During comparison only a single character will be unprotected.
    public class ProtectedStringList : IProtectedString
    {
        public int Length { get; private set; }
        private ProtectedStringNode head;
        private ProtectedStringNode tail;

        public void Append(char c)
        {
            ProtectedStringNode node = new ProtectedStringNode(c);
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
    }
}
