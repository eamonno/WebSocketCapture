using System;
using System.Text;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace SockSniffer
{
    // Records an entire websocket session. Removes itself from the associated packet producer when
    // the session is closed.
    public class WebSocketRecorder : IPacketConsumer
    {
        private IpV4Address _srcIp;
        private IpV4Address _dstIp;
        private ushort _srcPort;
        private ushort _dstPort;
        private DateTime _startTime = DateTime.Now;

        private readonly List<Packet> _packets = new List<Packet>();

        public WebSocketRecorder(IpV4Datagram ip)
        {
            _srcIp = ip.Source;
            _dstIp = ip.Destination;
            _srcPort = ip.Tcp.SourcePort;
            _dstPort = ip.Tcp.DestinationPort;
        }

        public void HandlePacket(IPacketProducer source, Packet packet)
        {
            // Ignore any packets that are not TCP packets on the same stream
            IpV4Datagram ip = packet.Ethernet.IpV4;
            if (!ip.IsValid)
                return;
            TcpDatagram tcp = ip.Tcp;
            if (!tcp.IsValid)
                return;
            if (ip.Source != _srcIp && ip.Source != _dstIp)
                return;
            if (ip.Source == _srcIp && (ip.Destination != _dstIp || tcp.SourcePort != _srcPort || tcp.DestinationPort != _dstPort))
                return;
            if (ip.Source == _dstIp && (ip.Destination != _srcIp || tcp.SourcePort != _dstPort || tcp.DestinationPort != _srcPort))
                return;

            // Correct stream, save the packet
            _packets.Add(packet);

            string dir = ip.Source == _srcIp ? "->" : "<-";
            Console.Write($"WebSocketRecorder on stream: {_srcIp}:{_srcPort} {dir} {_dstIp}:{_dstPort} ({_packets.Count}) :: ");
            if (tcp.Http.IsValid)
            {
                if (tcp.Http.IsRequest && ((HttpRequestDatagram)tcp.Http).Method?.KnownMethod == HttpRequestKnownMethod.Get)
                {
                    Console.WriteLine("HTTP Upgrade Requested");
                    return;
                }
                if (tcp.Http.IsResponse && ((HttpResponseDatagram)tcp.Http).StatusCode == 101)
                {
                    Console.WriteLine("HTTP Upgrade Confirmed");
                    return;
                }
            }
            // Http.IsValid isn't terribly reliable, if none of the above matches just assume its websocket even if it
            // is reporting as valid http
            var ws = new WebSocketDatagram(tcp.Payload);
            if (ws.IsValid)
            {
                Console.Write($"Final: {ws.IsFinal}, Masked: {ws.IsMasked}, Opcode: {ws.Opcode}, PayloadLength: {ws.PayloadLength}");
                if (ws.Opcode == WebSocketDatagram.OpcodeType.TextFrame)
                {
                    Console.Write(Encoding.UTF8.GetString(ws.UnmaskedPayload));
                }
                else if (ws.Opcode == WebSocketDatagram.OpcodeType.Close)
                {
                    source.RemoveConsumer(this);
                    WritePcapFile();
                }
                Console.WriteLine();
            }
            else if (tcp.Payload.Length >= 2)   // 0 or 1 bytes is a TCP - Keep-Alive packet
            {
                Console.WriteLine($"Invalid WebSocket packet: {tcp.Payload.Length}");
            }
        }

        public void WritePcapFile()
        {
            string filename = $"websock__{_srcIp}_{_srcPort}__{_dstIp}_{_dstPort}__" + _packets[0].Timestamp.ToString("hh-mm-ss-fff") + ".pcap";
            PacketDumpFile.Dump(filename, DataLinkKind.Ethernet, 65536, _packets);
        }
    }
}
