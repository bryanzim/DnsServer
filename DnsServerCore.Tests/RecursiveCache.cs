using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class RecursiveCache : IClassFixture<DnsServerFixture>, IDisposable
    {
        readonly DnsServerFixture _dns;
        readonly UdpClient _upstream;
        readonly CancellationTokenSource _stop;
        int _upstreamQueries;

        public RecursiveCache(DnsServerFixture dns)
        {
            _dns = dns;
            _upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            _stop = new CancellationTokenSource();

            _ = Task.Run(AnswerUpstreamAsync);

            _dns.Server.DnssecValidation = false;
            _dns.Server.ForwarderRetries = 1;
            _dns.Server.ForwarderTimeout = 1000;
            _dns.Server.Forwarders = [new NameServerAddress((IPEndPoint)_upstream.Client.LocalEndPoint)];
        }

        public void Dispose()
        {
            _dns.Server.Forwarders = null;
            _stop.Cancel();
            _upstream.Dispose();
            _stop.Dispose();
        }

        [Fact]
        public async Task ForwardedAnswerIsServedFromCache()
        {
            const string name = "www.cached.example";

            DnsDatagram first = await QueryAsync(name);
            DnsDatagram second = await QueryAsync(name);

            Assert.Equal(DnsResponseCode.NoError, first.RCODE);
            Assert.Equal(IPAddress.Parse("192.0.2.50"), ((DnsARecordData)DnsTest.Find(first.Answer, DnsResourceRecordType.A, name).RDATA).Address);
            Assert.Equal(DnsServerResponseType.Cached, second.Tag);
            Assert.Equal(1, Volatile.Read(ref _upstreamQueries));

            List<DnsResourceRecord> stored = new List<DnsResourceRecord>();
            _dns.Server.CacheZoneManager.ListAllRecords(name, stored);
            Assert.Contains(stored, record => (record.Type == DnsResourceRecordType.A) && record.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

            List<string> zones = new List<string>();
            _dns.Server.CacheZoneManager.ListSubDomains("", zones);
            Assert.Contains("example", zones);
        }

        async Task AnswerUpstreamAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                UdpReceiveResult received;

                try
                {
                    received = await _upstream.ReceiveAsync(_stop.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                DnsDatagram query;

                using (MemoryStream input = new MemoryStream(received.Buffer, 0, received.Buffer.Length, false))
                    query = DnsDatagram.ReadFrom(input);

                Interlocked.Increment(ref _upstreamQueries);

                DnsQuestionRecord question = query.Question[0];
                DnsResourceRecord address = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.50")));
                DnsDatagram response = new DnsDatagram(query.Identifier, true, DnsOpcode.StandardQuery, true, false, query.RecursionDesired, true, false, false, DnsResponseCode.NoError, query.Question, [address]);

                using MemoryStream output = new MemoryStream();
                response.WriteTo(output);
                await _upstream.SendAsync(output.ToArray(), received.RemoteEndPoint);
            }
        }

        Task<DnsDatagram> QueryAsync(string name)
        {
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);
            return _dns.Server.DirectQueryAsync(request, 5000);
        }
    }
}
