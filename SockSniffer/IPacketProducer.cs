namespace SockSniffer
{
    // A packet producer produces network packets from a source and passes those packets on to
    // any IPacketConsumers which have been added to it.
    public interface IPacketProducer
    {
        void AddConsumer(IPacketConsumer consumer);
        void RemoveConsumer(IPacketConsumer consumer);
    }
}