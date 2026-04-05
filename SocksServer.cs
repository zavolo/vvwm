using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace VlessVPN
{
    public class SocksServer
    {
        private StreamSocketListener _listener;
        private VlessConfig _config;
        private CancellationTokenSource _cts;
        private int _activeConnections;
        public int Port { get; private set; }
        public event Action<string> Log;

        public async Task StartAsync(VlessConfig config, int port)
        {
            _config = config;
            Port = port;
            _cts = new CancellationTokenSource();
            _activeConnections = 0;

            _listener = new StreamSocketListener();
            _listener.ConnectionReceived += OnConnectionReceived;
            _listener.Control.KeepAlive = true;

            await _listener.BindServiceNameAsync(port.ToString());
            Log?.Invoke($"SOCKS5 listening on 127.0.0.1:{port}");
        }

        public void Stop()
        {
            _cts?.Cancel();
            _listener?.Dispose();
            _listener = null;
            Log?.Invoke("SOCKS5 stopped");
        }

        private async void OnConnectionReceived(StreamSocketListener sender, StreamSocketListenerConnectionReceivedEventArgs args)
        {
            Interlocked.Increment(ref _activeConnections);
            StreamSocket remoteSocket = null;

            try
            {
                using (var client = args.Socket)
                {
                    var reader = new DataReader(client.InputStream);
                    var writer = new DataWriter(client.OutputStream);
                    reader.InputStreamOptions = InputStreamOptions.Partial;

                    await reader.LoadAsync(2);
                    byte socksVer = reader.ReadByte();
                    byte nMethods = reader.ReadByte();

                    if (socksVer != 0x05)
                        return;

                    if (nMethods > 0)
                    {
                        await reader.LoadAsync(nMethods);
                        byte[] methods = new byte[nMethods];
                        reader.ReadBytes(methods);
                    }

                    writer.WriteByte(0x05);
                    writer.WriteByte(0x00);
                    await writer.StoreAsync();

                    await reader.LoadAsync(4);
                    byte ver = reader.ReadByte();
                    byte cmd = reader.ReadByte();
                    byte rsv = reader.ReadByte();
                    byte atyp = reader.ReadByte();

                    if (cmd != 0x01)
                    {
                        writer.WriteByte(0x05);
                        writer.WriteByte(0x07);
                        writer.WriteByte(0x00);
                        writer.WriteByte(0x01);
                        writer.WriteBytes(new byte[6]);
                        await writer.StoreAsync();
                        return;
                    }

                    byte[] destAddr;
                    string destHost;

                    if (atyp == 0x01)
                    {
                        await reader.LoadAsync(4);
                        destAddr = new byte[4];
                        reader.ReadBytes(destAddr);
                        destHost = $"{destAddr[0]}.{destAddr[1]}.{destAddr[2]}.{destAddr[3]}";
                    }
                    else if (atyp == 0x03)
                    {
                        await reader.LoadAsync(1);
                        byte domainLen = reader.ReadByte();
                        await reader.LoadAsync(domainLen);
                        destAddr = new byte[domainLen];
                        reader.ReadBytes(destAddr);
                        destHost = Encoding.ASCII.GetString(destAddr);
                    }
                    else if (atyp == 0x04)
                    {
                        await reader.LoadAsync(16);
                        destAddr = new byte[16];
                        reader.ReadBytes(destAddr);
                        destHost = "[IPv6]";
                    }
                    else
                    {
                        return;
                    }

                    await reader.LoadAsync(2);
                    byte portHi = reader.ReadByte();
                    byte portLo = reader.ReadByte();
                    int destPort = (portHi << 8) | portLo;

                    Log?.Invoke($"-> {destHost}:{destPort}");

                    remoteSocket = new StreamSocket();
                    remoteSocket.Control.KeepAlive = true;
                    remoteSocket.Control.NoDelay = true;

                    if (_config.Security == "tls" || _config.Security == "reality")
                    {
                        if (_config.Security == "reality")
                        {
                            remoteSocket.Control.IgnorableServerCertificateErrors.Add(
                                Windows.Security.Cryptography.Certificates.ChainValidationResult.Untrusted);
                            remoteSocket.Control.IgnorableServerCertificateErrors.Add(
                                Windows.Security.Cryptography.Certificates.ChainValidationResult.InvalidName);
                        }

                        await remoteSocket.ConnectAsync(
                            new HostName(_config.Address),
                            _config.Port.ToString(),
                            SocketProtectionLevel.Tls12);
                    }
                    else
                    {
                        await remoteSocket.ConnectAsync(
                            new HostName(_config.Address),
                            _config.Port.ToString(),
                            SocketProtectionLevel.PlainSocket);
                    }

                    byte[] vlessHeader = BuildVlessRequest(destAddr, atyp, destPort);
                    var remoteWriter = new DataWriter(remoteSocket.OutputStream);
                    remoteWriter.WriteBytes(vlessHeader);
                    await remoteWriter.StoreAsync();

                    writer.WriteByte(0x05);
                    writer.WriteByte(0x00);
                    writer.WriteByte(0x00);
                    writer.WriteByte(0x01);
                    writer.WriteBytes(new byte[] { 0, 0, 0, 0 });
                    writer.WriteByte(portHi);
                    writer.WriteByte(portLo);
                    await writer.StoreAsync();

                    var remoteReader = new DataReader(remoteSocket.InputStream);
                    remoteReader.InputStreamOptions = InputStreamOptions.Partial;

                    bool responseHeaderRead = false;

                    var t1 = Task.Run(async () =>
                    {
                        byte[] buf = new byte[8192];
                        try
                        {
                            while (!_cts.IsCancellationRequested)
                            {
                                uint n = await reader.LoadAsync(8192);
                                if (n == 0) break;
                                byte[] data = new byte[n];
                                reader.ReadBytes(data);
                                remoteWriter.WriteBytes(data);
                                await remoteWriter.StoreAsync();
                            }
                        }
                        catch { }
                    });

                    var t2 = Task.Run(async () =>
                    {
                        try
                        {
                            while (!_cts.IsCancellationRequested)
                            {
                                uint n = await remoteReader.LoadAsync(8192);
                                if (n == 0) break;

                                if (!responseHeaderRead)
                                {
                                    byte respVer = remoteReader.ReadByte();
                                    byte addonLen = remoteReader.ReadByte();
                                    n -= 2;
                                    if (addonLen > 0)
                                    {
                                        byte[] skip = new byte[addonLen];
                                        remoteReader.ReadBytes(skip);
                                        n -= addonLen;
                                    }
                                    responseHeaderRead = true;
                                }

                                if (n > 0)
                                {
                                    byte[] data = new byte[n];
                                    remoteReader.ReadBytes(data);
                                    writer.WriteBytes(data);
                                    await writer.StoreAsync();
                                }
                            }
                        }
                        catch { }
                    });

                    await Task.WhenAny(t1, t2);

                    remoteReader.Dispose();
                    remoteWriter.Dispose();
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Conn error: {ex.Message}");
            }
            finally
            {
                remoteSocket?.Dispose();
                Interlocked.Decrement(ref _activeConnections);
            }
        }

        private byte[] BuildVlessRequest(byte[] destAddr, byte atyp, int destPort)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0);

                string hex = _config.Uuid.Replace("-", "");
                byte[] uuid = new byte[16];
                for (int i = 0; i < 16; i++)
                    uuid[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                ms.Write(uuid, 0, 16);

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

                if (atyp == 0x01)
                {
                    ms.WriteByte(0x01);
                    ms.Write(destAddr, 0, 4);
                }
                else if (atyp == 0x04)
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

                return ms.ToArray();
            }
        }
    }
}