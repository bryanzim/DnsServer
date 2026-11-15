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
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.ApplicationCommon
{
    public static class NegativeCache
    {
        //RFC 2308 section 3: a negative answer caches for min(SOA TTL, SOA MINIMUM).
        public static IReadOnlyList<DnsResourceRecord> WithNegativeCacheTtl(IReadOnlyList<DnsResourceRecord> records)
        {
            DnsResourceRecord? soaRecord = null;

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type == DnsResourceRecordType.SOA)
                {
                    soaRecord = record;
                    break;
                }
            }

            if (soaRecord?.RDATA is not DnsSOARecordData soa)
                return records;

            uint negativeTtl = Math.Min(soaRecord.OriginalTtlValue, soa.Minimum);
            if (negativeTtl == soaRecord.OriginalTtlValue)
                return records;

            DnsResourceRecord[] copy = new DnsResourceRecord[records.Count];

            for (int i = 0; i < records.Count; i++)
            {
                DnsResourceRecord record = records[i];

                if ((record.Type == DnsResourceRecordType.SOA) || ((record.Type == DnsResourceRecordType.RRSIG) && (record.RDATA is DnsRRSIGRecordData rrsig) && (rrsig.TypeCovered == DnsResourceRecordType.SOA)))
                    copy[i] = new DnsResourceRecord(record.Name, record.Type, record.Class, negativeTtl, record.RDATA) { Tag = record.Tag };
                else
                    copy[i] = record;
            }

            return copy;
        }
    }
}
