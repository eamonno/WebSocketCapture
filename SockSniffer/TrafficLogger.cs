using System;
using System.Text;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace SockSniffer
{
    // Logging packet consumer. Prints information to the console about any traffic being sent its way
    public class TrafficLogger : IPacketConsumer
    {
        public void HandlePacket(IPacketProducer source, Packet packet)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            TcpDatagram tcp = ip.Tcp;

            var msg = new StringBuilder();
            msg.Append(packet.Timestamp.ToString("hh:mm:ss.fff"));
            msg.Append(" (").Append(packet.Length).Append(") ");
            if (tcp.IsValid)
            {
                msg.Append(ip.Source).Append(":").Append(tcp.SourcePort).Append(" -> ");
                msg.Append(ip.Destination).Append(":").Append(tcp.DestinationPort).Append(' ');
                if (tcp.Http.IsRequest && ((HttpRequestDatagram)tcp.Http).Method != null)
                {
                    var http = (HttpRequestDatagram)tcp.Http;
                    msg.Append(http.Method?.Method ?? "???").Append(' ').Append(http.Uri).Append(' ').Append(http.Version);
                }
                else if (tcp.Http.IsResponse)
                {
                    var http = (HttpResponseDatagram)tcp.Http;
                    msg.Append(http.StatusCode).Append(' ').Append(http.ReasonPhrase);
                }
            }
            else
            {
                msg.Append(ip.Source).Append(" -> ").Append(ip.Destination);
            }
            Console.WriteLine(msg);
        }
    }
}