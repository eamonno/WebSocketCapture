using System;
using System.Collections.Generic;

using PcapDotNet.Packets;

namespace SockSniffer
{
    // WebSocket datagram from within a Tcp packet
    public class WebSocketDatagram
    {
        [Flags]
        public enum FlagBits
        {
            Final = 0x8000,
            RSV1 = 0x4000,
            RSV2 = 0x2000,
            RSV3 = 0x1000,
            RSV = RSV1 | RSV2 | RSV3,
            OpCode = 0xF00,
            Masked = 0x80,
            Length = 0x7F,
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

        public bool IsValid
        {
            get
            {
                if (_data.Length < 2)
                    return false;
                if (_data.Length < 2 + LengthBytes)
                    return false;
                if (_data.Length != 2 + LengthBytes + (IsMasked ? 4 : 0) + (int)PayloadLength)
                    return false;
                return true;
            }
        }

        public OpcodeType Opcode => (OpcodeType)((((int)Flags & (int)FlagBits.OpCode)) >> 8);

        public byte LengthInfo => (byte)(_data[1] & 0x7f);
        public int LengthBytes => LengthInfo < 126 ? 0 : LengthInfo == 126 ? 2 : 8;

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
                int offset = 2 + LengthBytes + (IsMasked ? 4 : 0);
                return _data.Subsegment(offset, _data.Length - offset);
            }
        }

        public byte[] UnmaskedPayload
        {
            get
            {
                var bytes = new List<byte>();

                if (IsMasked == false)
                {
                    foreach (byte b in Payload)
                        bytes.Add(b);
                }
                else
                {
                    int maskByte = 0;
                    foreach (byte b in Payload)
                    {
                        bytes.Add((byte)(b ^ _data[2 + LengthBytes + maskByte]));
                        maskByte = (maskByte + 1) % 4;
                    }
                }
                return bytes.ToArray();
            }
        }
    }
}