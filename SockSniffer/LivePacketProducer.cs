using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;

namespace SockSniffer
{
    // A packet producer that produces packets from a LivePacketDevice, thereby facilitiating realtime
    // analysis of network traffic. 
    public class LivePacketProducer : IPacketProducer, IDisposable
    {
        private List<IPacketConsumer> _consumers = new List<IPacketConsumer>();
        private List<IPacketConsumer> _newConsumers = new List<IPacketConsumer>();
        private List<IPacketConsumer> _oldConsumers = new List<IPacketConsumer>();
        private LivePacketDevice _device;
        private PacketCommunicator _comminicator;
        private BerkeleyPacketFilter _filter;

        public LivePacketProducer(LivePacketDevice device)
        {
            if (device == null)
                throw new ArgumentException("Device must not be null");

            _device = device;

            _comminicator = _device.Open(65536, PacketDeviceOpenAttributes.MaximumResponsiveness | PacketDeviceOpenAttributes.Promiscuous, 0);
            if (_comminicator.DataLink.Kind != DataLinkKind.Ethernet)
                throw new ArgumentException("Only Ethernet devices are supported for live packet production.");

            _filter = _comminicator.CreateFilter("ip and tcp");
            if (_filter != null)
                _comminicator.SetFilter(_filter);
        }

        public void AddConsumer(IPacketConsumer consumer) => _newConsumers.Add(consumer);

        public void RemoveConsumer(IPacketConsumer consumer) => _oldConsumers.Add(consumer);

        public void UpdateForever()
        {
            while (true)
                UpdateOnce();
        }

        public void UpdateOnce()
        {
            _consumers.AddRange(_newConsumers);
            _newConsumers.Clear();
            foreach (var old in _oldConsumers)
                _consumers.Remove(old);
            _oldConsumers.Clear();

            Packet packet;
            if (_comminicator.ReceivePacket(out packet) == PacketCommunicatorReceiveResult.Ok)
                foreach (IPacketConsumer consumer in _consumers)
                    consumer.HandlePacket(this, packet);
        }

        public void Dispose()
        {
            _filter?.Dispose();
            _comminicator?.Dispose();
        }
    }
}