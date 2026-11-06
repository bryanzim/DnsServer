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

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace ZoneAlias
{
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        IDnsServer _dnsServer;

        byte _appPreference;

        bool _enableAliasing;
        Dictionary<string, string> _aliases;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region private

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private bool IsZoneAlias(string domain, out string zone, out string alias)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_aliases.TryGetValue(domain, out zone))
                {
                    //found alias
                    alias = domain;
                    return true;
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            alias = null;
            return false;
        }

        private static string AliasName(string name, string zone, string alias)
        {
            if (string.IsNullOrEmpty(name))
                return null;

            int j = name.LastIndexOf(zone, StringComparison.OrdinalIgnoreCase);
            bool atLabelBoundary = (j == 0) || ((j > 0) && (name[j - 1] == '.'));
            bool isSuffix = (j > -1) && ((j + zone.Length) == name.Length);

            if (!(atLabelBoundary && isSuffix))
                return null;

            if (j == 0)
                return alias;

            return string.Concat(name.AsSpan(0, j), alias);
        }

        private static DnsResourceRecordData AliasRecordData(DnsResourceRecord record, string zone, string alias)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.CNAME:
                    {
                        string domain = AliasName((record.RDATA as DnsCNAMERecordData).Domain, zone, alias);
                        if (domain is not null)
                            return new DnsCNAMERecordData(domain);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        string domain = AliasName((record.RDATA as DnsDNAMERecordData).Domain, zone, alias);
                        if (domain is not null)
                            return new DnsDNAMERecordData(domain);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = AliasName((record.RDATA as DnsNSRecordData).NameServer, zone, alias);
                        if (nameServer is not null)
                            return new DnsNSRecordData(nameServer);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        DnsMXRecordData mx = record.RDATA as DnsMXRecordData;
                        string exchange = AliasName(mx.Exchange, zone, alias);
                        if (exchange is not null)
                            return new DnsMXRecordData(mx.Preference, exchange);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        DnsSRVRecordData srv = record.RDATA as DnsSRVRecordData;
                        string target = AliasName(srv.Target, zone, alias);
                        if (target is not null)
                            return new DnsSRVRecordData(srv.Priority, srv.Weight, srv.Port, target);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string domain = AliasName((record.RDATA as DnsPTRRecordData).Domain, zone, alias);
                        if (domain is not null)
                            return new DnsPTRRecordData(domain);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                case DnsResourceRecordType.ALIAS:
                    {
                        string domain = AliasName((record.RDATA as DnsANAMERecordData).Domain, zone, alias);
                        if (domain is not null)
                        {
                            if (record.Type == DnsResourceRecordType.ALIAS)
                                return new DnsALIASRecordData((record.RDATA as DnsALIASRecordData).Type, domain);

                            return new DnsANAMERecordData(domain);
                        }
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        DnsSOARecordData soa = record.RDATA as DnsSOARecordData;
                        string primaryNameServer = AliasName(soa.PrimaryNameServer, zone, alias) ?? soa.PrimaryNameServer;
                        string responsiblePerson = AliasName(soa.ResponsiblePerson, zone, alias) ?? soa.ResponsiblePerson;

                        if (!primaryNameServer.Equals(soa.PrimaryNameServer, StringComparison.OrdinalIgnoreCase) || !responsiblePerson.Equals(soa.ResponsiblePerson, StringComparison.OrdinalIgnoreCase))
                            return new DnsSOARecordData(primaryNameServer, responsiblePerson, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum);
                    }
                    break;

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    {
                        DnsSVCBRecordData svcb = record.RDATA as DnsSVCBRecordData;
                        if (svcb is null)
                            break;

                        string targetName = AliasName(svcb.TargetName, zone, alias);
                        if (targetName is not null)
                            return new DnsSVCBRecordData(svcb.SvcPriority, targetName, svcb.SvcParams);
                    }
                    break;
            }

            return record.RDATA;
        }

        private static IReadOnlyList<DnsResourceRecord> ConvertRecords(IReadOnlyList<DnsResourceRecord> records, string zone, string alias)
        {
            if (records.Count == 0)
                return records;

            DnsResourceRecord[] newRecords = new DnsResourceRecord[records.Count];

            for (int i = 0; i < records.Count; i++)
            {
                DnsResourceRecord record = records[i];
                string name = AliasName(record.Name, zone, alias) ?? record.Name;
                DnsResourceRecordData rdata = AliasRecordData(record, zone, alias);

                if (name.Equals(record.Name, StringComparison.Ordinal) && ReferenceEquals(rdata, record.RDATA))
                    newRecords[i] = record;
                else
                    newRecords[i] = new DnsResourceRecord(name, record.Type, record.Class, record.TTL, rdata);
            }

            return newRecords;
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config, _jsonParseOptions);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _appPreference = Convert.ToByte(jsonConfig.GetPropertyValue("appPreference", 10));

            _enableAliasing = jsonConfig.GetPropertyValue("enableAliasing", true);

            if (jsonConfig.TryGetProperty("zoneAliases", out JsonElement jsonZoneAliases))
            {
                Dictionary<string, string> aliases = new Dictionary<string, string>();

                foreach (JsonProperty jsonZoneAlias in jsonZoneAliases.EnumerateObject())
                {
                    string zone = jsonZoneAlias.Name.ToLowerInvariant();

                    foreach (JsonElement jsonAlias in jsonZoneAlias.Value.EnumerateArray())
                        aliases.Add(jsonAlias.GetString().ToLowerInvariant(), zone);
                }

                aliases.TrimExcess();

                _aliases = aliases;
            }
            else
            {
                _aliases = null;
            }

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableAliasing || (_aliases is null))
                return null;

            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name;

            if (!IsZoneAlias(qname, out string zone, out string alias))
                return null;

            string newQname;
            int i = qname.LastIndexOf(alias, StringComparison.OrdinalIgnoreCase);
            if (i == 0)
                newQname = zone;
            else if (i > 0)
                newQname = string.Concat(qname.AsSpan(0, i), zone);
            else
                return null;

            DnsQuestionRecord newQuestion = new DnsQuestionRecord(newQname, question.Type, question.Class);

            ushort udpPayloadSize = ushort.MinValue;
            EDnsHeaderFlags ednsFlags = EDnsHeaderFlags.None;
            IReadOnlyList<EDnsOption> options = null;

            if (request.EDNS is not null)
            {
                udpPayloadSize = request.EDNS.UdpPayloadSize < 512 ? (ushort)512 : request.EDNS.UdpPayloadSize;
                ednsFlags = request.EDNS.Flags;
            }

            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
            if (requestECS is not null)
            {
                options = [new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, requestECS)];

                if (udpPayloadSize < 512)
                    udpPayloadSize = 512;
            }

            DnsDatagram aliasRequest = new DnsDatagram(request.Identifier, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, request.CheckingDisabled, DnsResponseCode.NoError, [newQuestion], null, null, null, udpPayloadSize, ednsFlags, options);

            try
            {
                DnsDatagram response = await _dnsServer.DirectQueryAsync(aliasRequest, remoteEP);

                IReadOnlyList<DnsResourceRecord> newAnswer = ConvertRecords(response.Answer, zone, alias);
                IReadOnlyList<DnsResourceRecord> newAuthority = ConvertRecords(response.Authority, zone, alias);
                IReadOnlyList<DnsResourceRecord> newAdditional = ConvertRecords(response.Additional, zone, alias);

                return new DnsDatagram(request.Identifier, true, request.OPCODE, response.AuthoritativeAnswer, response.Truncation, request.RecursionDesired, isRecursionAllowed, false, false, response.RCODE, request.Question, newAnswer, newAuthority, newAdditional) { Tag = response.Tag };
            }
            catch (TimeoutException)
            { }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }

            return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.ServerFailure, request.Question);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Allows configuring aliases for any zone (internal or external) such that they all return the same set of records."; } }

        public byte Preference
        { get { return _appPreference; } }

        #endregion
    }
}
