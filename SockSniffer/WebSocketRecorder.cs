using System;
using System.Collections.Generic;
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

        private List<Packet> _packets = new List<Packet>();

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

            if (tcp.Http.IsValid && tcp.Http.IsRequest && ((HttpRequestDatagram)tcp.Http).Method.KnownMethod == HttpRequestKnownMethod.Get)
            {
                Console.WriteLine("Http Handshake");
            }
            else
            {
                var ws = tcp.WebSocket();
                Console.WriteLine($"Final: {ws.IsFinal}, Masked: {ws.IsMasked}, Opcode: {ws.Opcode}, PayloadLength: {ws.PayloadLength}");
            }
            Console.WriteLine(ToString());
        }

        public override string ToString() => $"WebSocketRecorder on stream: {_srcIp}:{_srcPort} -> {_dstIp}:{_dstPort} ({_packets.Count})";
    }
}