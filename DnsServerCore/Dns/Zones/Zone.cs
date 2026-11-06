/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    abstract class Zone
    {
        #region variables

        protected readonly string _name;
        protected readonly ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries;

        #endregion

        #region constructor

        protected Zone(string name)
        {
            _name = name.ToLowerInvariant();
            _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, 5);
        }

        protected Zone(string name, int capacity)
        {
            _name = name.ToLowerInvariant();
            _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, capacity);
        }

        protected Zone(string name, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries)
        {
            _name = name.ToLowerInvariant();
            _entries = entries;
        }

        #endregion

        #region static

        public static string GetReverseZone(IPAddress address, IPAddress subnetMask)
        {
            return GetReverseZone(address, subnetMask.GetSubnetMaskWidth());
        }

        public static string GetReverseZone(IPAddress address, int subnetMaskWidth)
        {
            byte[] addressBytes = address.GetAddressBytes();
            string reverseZone = "";

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                {
                    int octetCount = subnetMaskWidth / 8;

                    if (((subnetMaskWidth % 8) != 0) && (octetCount < 4))
                        octetCount++;

                    //a partial last octet is host bits (/25 through /31); use the enclosing octet zone
                    if (((subnetMaskWidth % 8) != 0) && (octetCount == 4) && (subnetMaskWidth < 32))
                        octetCount = 3;

                    for (int i = 0; i < octetCount; i++)
                        reverseZone = addressBytes[i] + "." + reverseZone;

                    reverseZone += "in-addr.arpa";
                    break;
                }

                case AddressFamily.InterNetworkV6:
                {
                    int nibbleCount = subnetMaskWidth / 4;

                    if (((subnetMaskWidth % 4) != 0) && (nibbleCount < 32))
                        nibbleCount++;

                    //a partial final nibble is host bits; use the enclosing nibble zone
                    if (((subnetMaskWidth % 4) != 0) && (nibbleCount == 32) && (subnetMaskWidth < 128))
                        nibbleCount = 31;

                    for (int n = 0; n < nibbleCount; n++)
                    {
                        int nibble = ((n % 2) == 0) ? (addressBytes[n / 2] >> 4) : (addressBytes[n / 2] & 0x0F);
                        reverseZone = nibble.ToString("x") + "." + reverseZone;
                    }

                    reverseZone += "ip6.arpa";
                    break;
                }

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            return reverseZone;
        }

        #endregion

        #region public

        public virtual void ListAllRecords(List<DnsResourceRecord> records)
        {
            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                records.AddRange(entry.Value);
        }

        public abstract bool ContainsNameServerRecords();

        public abstract bool ContainsDNAMERecord();

        public override string ToString()
        {
            return _name;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public virtual bool IsEmpty
        { get { return _entries.IsEmpty; } }

        #endregion
    }
}
