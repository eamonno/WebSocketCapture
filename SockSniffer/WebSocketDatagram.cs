using System;
using PcapDotNet.Packets;

namespace SockSniffer
{
    // WebSocket datagram from within a Tcp packet
    public class WebSocketDatagram
    {
        [Flags]
        public enum FlagBits
        {
            Final = 0x1,
            RSV1 = 0x2,
            RSV2 = 0x4,
            RSV3 = 0x8,
            RSV = RSV1 | RSV2 | RSV3,
            OpCode = 0xF0,
            Masked = 0x100,
            Length = 0xFE00,
        }

        public enum OpcodeType
        {
            Continuation = 0,
            TextFrame = 1,
            BinaryFrame = 2,
            Close = 8,
            Ping = 9,
            Pong = 10
        }

        private Datagram _data;

        public WebSocketDatagram(Datagram data)
        {
            _data = data;
        }

        public FlagBits Flags => (FlagBits)_data.ToUInt16(0);

        public bool IsFinal => (Flags & FlagBits.Final) != 0;
        public bool IsMasked => (Flags & FlagBits.Masked) != 0;
        public OpcodeType Opcode => (OpcodeType)(((int)Flags & (int)FlagBits.OpCode) >> 4);

        public byte LengthInfo => (byte)(_data[1] >> 1);
        public ulong PayloadLength => LengthInfo < 126 ? LengthInfo : LengthInfo == 126 ? _data.ToUInt16(2) : _data.ToULong(2);

        public ulong? MaskingKey
        {
            get
            {
                if (!IsMasked)
                    return null;
                byte b = LengthInfo;
                if (b < 126)
                    return _data.ToUInt32(2);
                if (b == 126)
                    return _data.ToUInt32(4);
                // at this point we know byteLength == 127
                return _data.ToUInt32(10);
            }
        }

        public DataSegment Payload
        {
            get
            {
                int offset = 2;
                if (LengthInfo == 126)
                    offset += 2;
                if (LengthInfo == 127)
                    offset += 8;
                if (IsMasked)
                    offset += 4;
                return _data.Subsegment(offset, _data.Length - offset);
            }
        }
    }
}