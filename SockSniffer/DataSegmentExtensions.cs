using PcapDotNet.Packets;

namespace SockSniffer
{
    // The PcapDotNet library uses a class called DataSegment internally to repreent byte arrays. While
    // the package does have plenty functions for extracting data unfortunately they are all internal
    // so I define a couple of my own helper functions. The names here match those of the System.BitConverter
    // class
    public static class DataSegmentExtensions
    {
        public static ushort ToUInt16(this DataSegment ds, int offset) => (ushort)((ds[offset] << 8) + ds[1 + offset]);

        public static uint ToUInt32(this DataSegment ds, int offset)
        {
            return (((uint)ds[3 + offset]) << 24) + (((uint)ds[2 + offset]) << 16)
                   + (((uint)ds[1 + offset]) << 8) + ds[offset];
        }

        public static ulong ToULong(this DataSegment ds, int offset)
        {
            return (((ulong)ds[7 + offset]) << 56) + (((ulong)ds[6 + offset]) << 48)
                   + (((ulong)ds[5 + offset]) << 40) + (((ulong)ds[4 + offset]) << 32)
                   + (((ulong)ds[3 + offset]) << 24) + (((ulong)ds[2 + offset]) << 16)
                   + (((ulong)ds[1 + offset]) << 8) + ds[offset];
        }
    }
}