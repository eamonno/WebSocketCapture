using PcapDotNet.Packets.Transport;

namespace SockSniffer
{
    // Define an extension for the TcpDatagram to allow extraction of WebSocket data
    public static class TcpDatagramExtensions
    {
        //public static WebSocketDatagram WebSocket(this TcpDatagram tcp) => new WebSocketDatagram(tcp.Payload);
    }
}