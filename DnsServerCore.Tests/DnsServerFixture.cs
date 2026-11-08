using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 6781, 7129, 7218, 7583, 7671, and 9276 are operational guidance and have no response to assert.
    // Datagram, EDNS, and TSIG round trips belong in TechnitiumLibrary.Net.
    // DoT, DoH, DoQ, and XFR-over-TLS bind listeners and stay in a separate project.
    // DHCP is a separate server.
    public sealed class DnsServerFixture : IAsyncLifetime
    {
        string _folder;
        LogManager _log;

        public DnsServer Server { get; private set; }

        public async Task InitializeAsync()
        {
            _folder = Path.Combine(Path.GetTempPath(), "dnsserver-tests-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(_folder);
            Directory.CreateDirectory(Path.Combine(_folder, "dohwww"));

            _log = new LogManager(true, _folder);
            _log.LoggingType = LoggingType.None;

            Server = new DnsServer(_folder, Path.Combine(_folder, "dohwww"), _log, "ns.example");

            await Task.CompletedTask;
        }

        public async Task DisposeAsync()
        {
            if (Server is not null)
                await Server.DisposeAsync();

            if (_log is not null)
                await _log.DisposeAsync();

            if ((_folder is not null) && Directory.Exists(_folder))
                Directory.Delete(_folder, true);
        }

        public AuthZoneInfo CreateZone(string zoneName)
        {
            AuthZoneInfo zone = Server.AuthZoneManager.CreatePrimaryZone(zoneName);
            Assert.NotNull(zone);
            return zone;
        }

        public void Add(string zoneName, string name, DnsResourceRecordType type, DnsResourceRecordData data, uint ttl = 300)
        {
            DnsResourceRecord record = new DnsResourceRecord(name, type, DnsClass.IN, ttl, data);
            Assert.True(Server.AuthZoneManager.AddRecord(zoneName, record), name + " " + type + " was not added");
        }

        public void Set(string zoneName, string name, DnsResourceRecordType type, DnsResourceRecordData data, uint ttl = 300)
        {
            Server.AuthZoneManager.SetRecords(zoneName, [new DnsResourceRecord(name, type, DnsClass.IN, ttl, data)]);
        }

        public Task<DnsDatagram> QueryAsync(string name, DnsResourceRecordType type, bool dnssecOk = false)
        {
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, type, DnsClass.IN)], udpPayloadSize: dnssecOk ? (ushort)1232 : ushort.MinValue, ednsFlags: dnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None);
            return Server.DirectQueryAsync(request, 10000);
        }

        public Task<DnsDatagram> QueryAsync(DnsDatagram request)
        {
            return Server.DirectQueryAsync(request, 10000);
        }
    }

    static class DnsTest
    {
        public static DnsResourceRecord Record(string name, DnsResourceRecordType type, DnsClass @class, uint ttl, DnsResourceRecordData data)
        {
            return new DnsResourceRecord(name, type, @class, ttl, data);
        }

        public static DnsDatagram RoundTrip(DnsDatagram message)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                message.WriteTo(stream);
                stream.Position = 0;
                return DnsDatagram.ReadFrom(stream);
            }
        }

        public static List<DnsResourceRecord> AllAnswers(DnsDatagram response)
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            for (DnsDatagram current = response; current is not null; current = current.NextDatagram)
                records.AddRange(current.Answer);

            return records;
        }

        public static DnsResourceRecord Find(IReadOnlyList<DnsResourceRecord> records, DnsResourceRecordType type, string name = null)
        {
            if (records is null)
                return null;

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type != type)
                    continue;

                if ((name is null) || record.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return record;
            }

            return null;
        }

        public static bool ContainsType(IReadOnlyList<DnsResourceRecord> records, DnsResourceRecordType type)
        {
            return Find(records, type) is not null;
        }

        public static string Describe(DnsDatagram response)
        {
            return response.RCODE + " AA=" + response.AuthoritativeAnswer + " answer=[" + Types(response.Answer) + "] authority=[" + Types(response.Authority) + "]";
        }

        static string Types(IReadOnlyList<DnsResourceRecord> records)
        {
            if ((records is null) || (records.Count == 0))
                return "";

            string text = records[0].Name + " " + records[0].Type;

            for (int i = 1; i < records.Count; i++)
                text += ", " + records[i].Name + " " + records[i].Type;

            return text;
        }
    }
}
