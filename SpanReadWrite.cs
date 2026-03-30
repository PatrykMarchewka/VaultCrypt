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
        /// Reads single byte and advances index counter by one
        /// </summary>
        /// <returns>Byte read from data at current index</returns>
        /// <exception cref="InvalidOperationException">Thrown when value cannot be read as it goes outside the array</exception>
        public byte ReadByte()
        {
            if(_data.Length == _index) throw new InvalidOperationException("Cannot read next byte from data");
            return _data[_index++];
        }

        /// <summary>
        /// Reads bytes number equal to <paramref name="length"/> and advances index counter by it
        /// </summary>
        /// <param name="length">Number of bytes to read</param>
        /// <returns>Bytes read from data at current index</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value cannot be read as it goes outside the array or when passed <paramref name="length"/> is equal or less than zero </exception>
        public byte[] ReadBytes(int length)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(_index + length, _data.Length);

            var result = _data.Slice(_index, length).ToArray();
            _index += length;
            return result;
        }

        /// <summary>
        /// Reads <see cref="ushort"/> from data and advances index counter by two
        /// </summary>
        /// <returns>UShort read from data at current index</returns>
        /// <exception cref="InvalidOperationException">Thrown when value cannot be read as it goes outside the array</exception>
        public ushort ReadUInt16()
        {
            if (_data.Length < _index + sizeof(ushort)) throw new InvalidOperationException("Cannot read value from data");

            ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_index, sizeof(ushort)));
            _index += sizeof(ushort);
            return value;
        }

        /// <summary>
        /// Reads <see cref="uint"/> from data and advances index counter by four
        /// </summary>
        /// <returns>UInt read from data at current index</returns>
        /// <exception cref="InvalidOperationException">Thrown when value cannot be read as it goes outside the array</exception>
        public uint ReadUInt32()
        {
            if (_data.Length < _index + sizeof(uint)) throw new InvalidOperationException("Cannot read value from data");

            uint value = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_index, sizeof(uint)));
            _index += sizeof(uint);
            return value;
        }

        /// <summary>
        /// Reads <see cref="ulong"/> from data and advances index counter by eight
        /// </summary>
        /// <returns>ULong read from data at current index</returns>
        /// <exception cref="InvalidOperationException">Thrown when value cannot be read as it goes outside the array</exception>
        public ulong ReadUInt64()
        {
            if (_data.Length < _index + sizeof(ulong)) throw new InvalidOperationException("Cannot read value from data");

            ulong value = BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_index, sizeof(ulong)));
            _index += sizeof(ulong);
            return value;
        }
    }

    public ref struct SpanWriter
    {
        private Span<byte> _data;
        private int _index;

        public SpanWriter(Span<byte> data)
        {
            if (data.IsEmpty) throw new ArgumentException("Provided empty data", nameof(data));

            _data = data;
            _index = 0;
        }

        /// <summary>
        /// Writes single byte and advances index counter by one
        /// </summary>
        /// <param name="value"></param>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="value"/> cannot fit in the Span</exception>
        public void WriteByte(byte value)
        {
            if (_index == _data.Length) throw new InvalidOperationException("Cannot write past Span length");
            _data[_index++] = value;
        }
        /// <summary>
        /// Writes span and advances index by its length
        /// </summary>
        /// <param name="value">ReadOnlySpan to write</param>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="value"/> cannot fit in the Span</exception>
        public void WriteSpan(ReadOnlySpan<byte> value)
        {
            if(_index + value.Length > _data.Length) throw new InvalidOperationException("Cannot write past Span length");
            value.CopyTo(_data.Slice(_index));
            _index += value.Length;
        }

        /// <summary>
        /// Writes <see cref="ushort"/> to span and advances index by two
        /// </summary>
        /// <param name="value"><see cref="ushort"/> to write</param>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="value"/> cannot fit in the Span</exception>
        public void WriteUInt16(ushort value)
        {
            if(_index + sizeof(ushort) > _data.Length) throw new InvalidOperationException("Cannot write past Span length");
            BinaryPrimitives.WriteUInt16LittleEndian(_data.Slice(_index), value);
            _index += sizeof(ushort);
        }

        /// <summary>
        /// Writes <see cref="uint"/> to span and advances index by four
        /// </summary>
        /// <param name="value"><see cref="uint"/> to write</param>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="value"/> cannot fit in the Span</exception>
        public void WriteUInt32(uint value)
        {
            if (_index + sizeof(uint) > _data.Length) throw new InvalidOperationException("Cannot write past Span length");
            BinaryPrimitives.WriteUInt32LittleEndian(_data.Slice(_index), value);
            _index += sizeof(uint);
        }

        /// <summary>
        /// Writes <see cref="ulong"/> to span and advances index by eight
        /// </summary>
        /// <param name="value"><see cref="ulong"/> to write</param>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="value"/> cannot fit in the Span</exception>
        public void WriteUInt64(ulong value)
        {
            if (_index + sizeof(ulong) > _data.Length) throw new InvalidOperationException("Cannot write past Span length");
            BinaryPrimitives.WriteUInt64LittleEndian(_data.Slice(_index), value);
            _index += sizeof(ulong);
        }
    }
}
