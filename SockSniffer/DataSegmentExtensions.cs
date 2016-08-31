using PcapDotNet.Packets;

namespace SockSniffer
{
    // The PcapDotNet library uses a class called DataSegment internally to repreent byte arrays. While
    // the package does have plenty functions for extracting data unfortunately they are all internal
    // so I define a couple of my own helper functions. The names here match those of the System.BitConverter
    // class
    public static class DataSegmentExtensions
    {
        public static ushort ToUInt16(this DataSegment ds, int offset) => (ushort)((int)ds[1] << 8 + (int)ds[0]);

        public static uint ToUInt32(this DataSegment ds, int offset)
        {
            return (((uint)ds[3]) << 24) + (((uint)ds[2]) << 16)
                   + (((uint)ds[1]) << 8) + ds[0];
        }

        public static ulong ToULong(this DataSegment ds, int offset)
        {
            return (((ulong)ds[7]) << 56) + (((ulong)ds[6]) << 48)
                   + (((ulong)ds[5]) << 40) + (((ulong)ds[4]) << 32)
                   + (((ulong)ds[3]) << 24) + (((ulong)ds[2]) << 16)
                   + (((ulong)ds[1]) << 8) + ds[0];
        }
    }
}