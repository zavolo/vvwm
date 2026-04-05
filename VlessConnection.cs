using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography.Certificates;
using Windows.Storage.Streams;

namespace VlessVPN
{
    public class VlessConnection : IDisposable
    {
        private StreamSocket _socket;
        private readonly VlessConfig _config;
        private DataWriter _writer;
        private DataReader _reader;
        private bool _headerSent;

        public VlessConnection(VlessConfig config)
        {
            _config = config;
        }

        public async Task ConnectAsync(CancellationToken ct)
        {
            _socket = new StreamSocket();

            _socket.Control.KeepAlive = true;
            _socket.Control.NoDelay = true;

            if (_config.Security == "tls" || _config.Security == "reality")
            {
                _socket.Control.ClientCertificate = null;

                if (_config.Security == "reality")
                {
                    _socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
                    _socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
                }
            }

            var host = new HostName(_config.Address);
            string serviceName = _config.Port.ToString();

            if (_config.Security == "tls" || _config.Security == "reality")
            {
                string sni = !string.IsNullOrEmpty(_config.Sni) ? _config.Sni : _config.Address;
                await _socket.ConnectAsync(host, serviceName, SocketProtectionLevel.Tls12);
            }
            else
            {
                await _socket.ConnectAsync(host, serviceName, SocketProtectionLevel.PlainSocket);
            }

            _writer = new DataWriter(_socket.OutputStream);
            _reader = new DataReader(_socket.InputStream);
            _reader.InputStreamOptions = InputStreamOptions.Partial;
            _headerSent = false;
        }

        public async Task<int> SendAsync(byte[] destAddress, int destPort, byte[] payload, int offset, int count)
        {
            if (!_headerSent)
            {
                byte[] header = BuildRequestHeader(destAddress, destPort, payload, offset, count);
                _writer.WriteBytes(header);
                await _writer.StoreAsync();
                _headerSent = true;
                return count;
            }

            _writer.WriteBytes(SubArray(payload, offset, count));
            await _writer.StoreAsync();
            return count;
        }

        public async Task<int> ReceiveAsync(byte[] buffer, int offset, int maxCount)
        {
            uint loaded = await _reader.LoadAsync((uint)maxCount);
            if (loaded == 0)
                return 0;

            if (!_headerSent)
            {
                int read = (int)Math.Min(loaded, (uint)maxCount);
                byte[] temp = new byte[read];
                _reader.ReadBytes(temp);
                Buffer.BlockCopy(temp, 0, buffer, offset, read);
                return read;
            }

            if (loaded >= 2)
            {
                byte version = _reader.ReadByte();
                byte addonLen = _reader.ReadByte();
                if (addonLen > 0)
                {
                    byte[] skip = new byte[addonLen];
                    _reader.ReadBytes(skip);
                    loaded -= (uint)(2 + addonLen);
                }
                else
                {
                    loaded -= 2;
                }
                _headerSent = false;
            }

            int toRead = (int)Math.Min(loaded, (uint)maxCount);
            if (toRead > 0)
            {
                byte[] temp = new byte[toRead];
                _reader.ReadBytes(temp);
                Buffer.BlockCopy(temp, 0, buffer, offset, toRead);
            }
            return toRead;
        }

        private byte[] BuildRequestHeader(byte[] destAddr, int destPort, byte[] payload, int offset, int count)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0);

                byte[] uuidBytes = ParseUuid(_config.Uuid);
                ms.Write(uuidBytes, 0, 16);

                if (!string.IsNullOrEmpty(_config.Flow))
                {
                    byte[] flowBytes = Encoding.UTF8.GetBytes(_config.Flow);
                    ms.WriteByte((byte)(flowBytes.Length + 2));
                    ms.WriteByte(0x0A);
                    ms.WriteByte((byte)flowBytes.Length);
                    ms.Write(flowBytes, 0, flowBytes.Length);
                }
                else
                {
                    ms.WriteByte(0);
                }

                ms.WriteByte(0x01);

                ms.WriteByte((byte)(destPort >> 8));
                ms.WriteByte((byte)(destPort & 0xFF));

                if (destAddr.Length == 4)
                {
                    ms.WriteByte(0x01);
                    ms.Write(destAddr, 0, 4);
                }
                else if (destAddr.Length == 16)
                {
                    ms.WriteByte(0x03);
                    ms.Write(destAddr, 0, 16);
                }
                else
                {
                    ms.WriteByte(0x02);
                    ms.WriteByte((byte)destAddr.Length);
                    ms.Write(destAddr, 0, destAddr.Length);
                }

                ms.Write(payload, offset, count);
                return ms.ToArray();
            }
        }

        private static byte[] ParseUuid(string uuid)
        {
            string hex = uuid.Replace("-", "");
            byte[] bytes = new byte[16];
            for (int i = 0; i < 16; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        private static byte[] SubArray(byte[] data, int offset, int length)
        {
            byte[] result = new byte[length];
            Buffer.BlockCopy(data, offset, result, 0, length);
            return result;
        }

        public void Dispose()
        {
            _writer?.Dispose();
            _reader?.Dispose();
            _socket?.Dispose();
        }
    }
}