using System;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Http;

namespace SockSniffer
{
    // Listens to network traffic looking at http traffic to detect any websocket upgrades. If
    // it detects a websocket upgrade then it creates a new WebSocketRecorder and attaches it to
    // listen to the packet producer that produced the packet.
    public class WebSocketDetector : IPacketConsumer
    {
        public void HandlePacket(IPacketProducer source, Packet packet)
        {
            HttpDatagram http = packet.Ethernet.IpV4.Tcp.Http;

            if (http.IsValid && http.IsRequest)
            {
                var req = (HttpRequestDatagram)http;
                if (req.Method?.KnownMethod == HttpRequestKnownMethod.Get)
                {
                    // Compulsory fields for establishing a WebSocket connection
                    string host = null;
                    string upgrade = null;
                    string connection = null;
                    string secWebsocketKey = null;
                    string secWebsocketVersion = null;

                    foreach (HttpField field in req.Header)
                    {
                        if (field.Name.Equals("Host", StringComparison.OrdinalIgnoreCase))
                            host = field.ValueString;
                        if (field.Name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase))
                            upgrade = field.ValueString;
                        if (field.Name.Equals("Connection", StringComparison.OrdinalIgnoreCase))
                            connection = field.ValueString;
                        if (field.Name.Equals("Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase))
                            secWebsocketKey = field.ValueString;
                        if (field.Name.Equals("Sec-WebSocket-Version", StringComparison.OrdinalIgnoreCase))
                            secWebsocketVersion = field.ValueString;
                        //Console.WriteLine($"{field.Name}: {field.ValueString}");
                    }
                    if (host != null && upgrade != null && connection != null && secWebsocketKey != null && secWebsocketVersion != null)
                    {
                        Console.WriteLine("Starting Recording");
                        var recorder = new WebSocketRecorder(packet.Ethernet.IpV4);
                        recorder.HandlePacket(source, packet);
                        source.AddConsumer(recorder);
                    }
                    //WriteLine($"Http Get Detected {host} {upgrade} {connection} {secWebsocketKey} {secWebsocketVersion}");
                }
            }
        }
    }
}