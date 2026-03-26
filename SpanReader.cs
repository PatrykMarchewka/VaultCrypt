using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public ref struct SpanReader
    {
        private ReadOnlySpan<byte> _data;
        private int _index;

        public SpanReader(ReadOnlySpan<byte> data)
        {
            if(data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            _data = data;
            _index = 0;
        }

        /// <summary>
        /// Reads single byte and advanced index counter by one
        /// </summary>
        /// <returns>Byte read from data at current index</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value cannot be read as it goes outside the array</exception>
        public byte ReadByte()
        {
            if(_data.Length == _index) throw new ArgumentOutOfRangeException("Cannot read next byte from data");
            return _data[_index++];
        }

        /// <summary>
        /// Reads bytes number equal to <paramref name="length"/> and advances index counter by it
        /// </summary>
        /// <param name="length">Number of bytes to read</param>
        /// <returns>Bytes read from data at current index</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value cannot be read as it goes outside the array</exception>
        public byte[] ReadBytes(int length)
        {
            if (_data.Length < _index + length) throw new ArgumentOutOfRangeException("Cannot read all bytes from data");

            var result = _data.Slice(_index, length).ToArray();
            _index += length;
            return result;
        }

        /// <summary>
        /// Reads <see cref="ushort"/> from data and advances index counter by two
        /// </summary>
        /// <returns>UShort read from data at current index</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value cannot be read as it goes outside the array</exception>
        public ushort ReadUInt16()
        {
            if (_data.Length < _index + 2) throw new ArgumentOutOfRangeException("Cannot read value from data");

            ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_index, 2));
            _index += 2;
            return value;
        }

        /// <summary>
        /// Reads <see cref="uint"/> from data and advances index counter by eight
        /// </summary>
        /// <returns>UInt read from data at current index</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value cannot be read as it goes outside the array</exception>
        public uint ReadUInt32()
        {
            if (_data.Length < _index + 4) throw new ArgumentOutOfRangeException("Cannot read value from data");

            uint value = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_index, 4));
            _index += 4;
            return value;
        }

        /// <summary>
        /// Reads <see cref="ulong"/> from data and advances index counter by eight
        /// </summary>
        /// <returns>ULong read from data at current index</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value cannot be read as it goes outside the array</exception>
        public ulong ReadUInt64()
        {
            if (_data.Length < _index + 8) throw new ArgumentOutOfRangeException("Cannot read value from data");

            ulong value = BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_index, 8));
            _index += 8;
            return value;
        }
    }
}
