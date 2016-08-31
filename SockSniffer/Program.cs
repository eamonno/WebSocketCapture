using static System.Console;
using System;
using System.Collections.Generic;
using System.Text;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Http;
using PcapDotNet.Core;

namespace SockSniffer
{
    // A packet producer produces network packets from a source and passes those packets on to
    // any IPacketConsumers which have been added to it.
    public interface IPacketProducer
    {
        void AddConsumer(IPacketConsumer consumer);
        void RemoveConsumer(IPacketConsumer consumer);
    }

    // A packet consumer takes network packets which have been created by a packet producer and 
    // performs an operation using that packet. That can be logging, analysis or any other operation
    // upon the packet. Since the same packet gets passed to every consumer attached to a given 
    // producer the packet itself should not be modified as that may have undesirable affects on any
    // other consumers receiving the same packet.
    public interface IPacketConsumer
    {
        void HandlePacket(IPacketProducer source, Packet packet);
    }

    // A packet producer that produces packets from a LivePacketDevice, thereby facilitiating realtime
    // analysis of network traffic. 
    public class LivePacketProducer : IPacketProducer, IDisposable
    {
        private List<IPacketConsumer> _consumers = new List<IPacketConsumer>();
        private LivePacketDevice _device;
        private PacketCommunicator _communicator;
        private BerkeleyPacketFilter _filter;

        public LivePacketProducer(LivePacketDevice device)
        {
            if (device == null)
                throw new ArgumentException("Device must not be null");

            _device = device;

            _communicator = _device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 0);
            if (_communicator.DataLink.Kind != DataLinkKind.Ethernet)
                throw new ArgumentException("Only Ethernet devices are supported for live packet production.");

            _filter = _communicator.CreateFilter("ip and tcp");
            if (_filter != null)
                _communicator.SetFilter(_filter);
        }

        public void AddConsumer(IPacketConsumer consumer) => _consumers.Add(consumer);

        public void RemoveConsumer(IPacketConsumer consumer) => _consumers.Remove(consumer);

        public void UpdateForever()
        {
            while (true)
                UpdateOnce();
        }

        public void UpdateOnce()
        {
            Packet packet;
            if (_communicator.ReceivePacket(out packet) == PacketCommunicatorReceiveResult.Ok)
                foreach (IPacketConsumer consumer in _consumers)
                    consumer.HandlePacket(this, packet);
        }

        public void Dispose()
        {
            _filter?.Dispose();
            _communicator?.Dispose();
        }
    }

    // Logging packet consumer. Prints information to the console about any traffic being sent its way
    public class TrafficLogger : IPacketConsumer
    {
        public void HandlePacket(IPacketProducer source, Packet packet)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            TcpDatagram tcp = ip.Tcp;

            var msg = new StringBuilder();
            msg.Append(packet.Timestamp.ToString("hh:mm:ss.fff"));
            msg.Append(tcp.Http == null ? "  " : " *");
            msg.Append(" (").Append(packet.Length).Append(") ");
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
            WriteLine(msg);
        }
    }

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
                    }
                    WriteLine($"Http Get Detected {host} {upgrade} {connection} {secWebsocketKey} {secWebsocketVersion}");
                }
            }
        }
    }

    // Records an entire websocket session. Removes itself from the associated packet producer when
    // the session is closed.
    public class WebSocketRecorder : IPacketConsumer
    {
        public void HandlePacket(IPacketProducer source, Packet packet)
        {

        }
    }

    class Program
    {
        public static void Main(string[] args)
        {
            var producer = new LivePacketProducer(SelectListenDevice());
            producer.AddConsumer(new TrafficLogger());
            producer.AddConsumer(new WebSocketDetector());
            producer.UpdateForever();
        }

        // Enumerates all available devices to the console and prompts the user to choose one
        public static LivePacketDevice SelectListenDevice()
        {
            IList<LivePacketDevice> devices = LivePacketDevice.AllLocalMachine;

            if (devices.Count == 0)
            {
                WriteLine("No network interfaces found. Make sure WinPCap is installed.");
                return null;
            }

            // List the devices
            foreach (LivePacketDevice device in devices)
                WriteLine(device.DeviceInformation());

            // Have the user select a device
            int deviceNo = 0;
            while (deviceNo == 0)
            {
                WriteLine($"Choose an interface (1-{devices.Count}): ");
                if (!int.TryParse(ReadLine(), out deviceNo) || deviceNo < 1 || deviceNo > devices.Count)
                    deviceNo = 0;
            }
            return devices[deviceNo - 1];
        }
    }
}
