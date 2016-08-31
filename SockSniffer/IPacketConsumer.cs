using PcapDotNet.Packets;

namespace SockSniffer
{
    // A packet consumer takes network packets which have been created by a packet producer and 
    // performs an operation using that packet. That can be logging, analysis or any other operation
    // upon the packet. Since the same packet gets passed to every consumer attached to a given 
    // producer the packet itself should not be modified as that may have undesirable affects on any
    // other consumers receiving the same packet.
    public interface IPacketConsumer
    {
        void HandlePacket(IPacketProducer source, Packet packet);
    }
}