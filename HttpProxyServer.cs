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
    public class HttpProxyServer
    {
        private StreamSocketListener _listener;
        private VlessConfig _config;
        private CancellationTokenSource _cts;
        public int Port { get; private set; }
        public event Action<string> Log;

        public async Task StartAsync(VlessConfig config, int port)
        {
            _config = config;
            Port = port;
            _cts = new CancellationTokenSource();

            _listener = new StreamSocketListener();
            _listener.ConnectionReceived += OnConnectionReceived;
            _listener.Control.KeepAlive = true;

            await _listener.BindServiceNameAsync(port.ToString());
            Log?.Invoke($"HTTP proxy listening on 127.0.0.1:{port}");
        }

        public void Stop()
        {
            _cts?.Cancel();
            _listener?.Dispose();
            _listener = null;
        }

        private async void OnConnectionReceived(StreamSocketListener sender, StreamSocketListenerConnectionReceivedEventArgs args)
        {
            StreamSocket remoteSocket = null;

            try
            {
                using (var client = args.Socket)
                {
                    var reader = new DataReader(client.InputStream);
                    var writer = new DataWriter(client.OutputStream);
                    reader.InputStreamOptions = InputStreamOptions.Partial;

                    string requestLine = await ReadLineAsync(reader);
                    if (string.IsNullOrEmpty(requestLine))
                        return;

                    string[] parts = requestLine.Split(' ');
                    if (parts.Length < 3)
                        return;

                    string method = parts[0].ToUpper();
                    string target = parts[1];

                    while (true)
                    {
                        string headerLine = await ReadLineAsync(reader);
                        if (string.IsNullOrEmpty(headerLine))
                            break;
                    }

                    string destHost;
                    int destPort;

                    if (method == "CONNECT")
                    {
                        ParseHostPort(target, 443, out destHost, out destPort);
                    }
                    else
                    {
                        if (target.StartsWith("http://"))
                        {
                            var uri = new Uri(target);
                            destHost = uri.Host;
                            destPort = uri.Port;
                        }
                        else
                        {
                            ParseHostPort(target, 80, out destHost, out destPort);
                        }
                    }

                    Log?.Invoke($"-> {destHost}:{destPort}");

                    byte[] destAddr = Encoding.ASCII.GetBytes(destHost);

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

                    byte[] vlessHeader = BuildVlessRequest(destAddr, destPort);
                    var remoteWriter = new DataWriter(remoteSocket.OutputStream);
                    var remoteReader = new DataReader(remoteSocket.InputStream);
                    remoteReader.InputStreamOptions = InputStreamOptions.Partial;

                    if (method == "CONNECT")
                    {
                        remoteWriter.WriteBytes(vlessHeader);
                        await remoteWriter.StoreAsync();

                        byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                        writer.WriteBytes(response);
                        await writer.StoreAsync();
                    }
                    else
                    {
                        byte[] reqBytes = Encoding.ASCII.GetBytes(requestLine + "\r\n\r\n");
                        byte[] fullPayload = new byte[vlessHeader.Length + reqBytes.Length];
                        System.Buffer.BlockCopy(vlessHeader, 0, fullPayload, 0, vlessHeader.Length);
                        System.Buffer.BlockCopy(reqBytes, 0, fullPayload, vlessHeader.Length, reqBytes.Length);
                        remoteWriter.WriteBytes(fullPayload);
                        await remoteWriter.StoreAsync();
                    }

                    bool responseHeaderRead = false;

                    var t1 = Task.Run(async () =>
                    {
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
            }
        }

        private byte[] BuildVlessRequest(byte[] destHostBytes, int destPort)
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

                ms.WriteByte(0x02);
                ms.WriteByte((byte)destHostBytes.Length);
                ms.Write(destHostBytes, 0, destHostBytes.Length);

                return ms.ToArray();
            }
        }

        private static void ParseHostPort(string hostPort, int defaultPort, out string host, out int port)
        {
            int colonIdx = hostPort.LastIndexOf(':');
            if (colonIdx > 0 && int.TryParse(hostPort.Substring(colonIdx + 1), out port))
            {
                host = hostPort.Substring(0, colonIdx);
            }
            else
            {
                host = hostPort;
                port = defaultPort;
            }
        }

        private static async Task<string> ReadLineAsync(DataReader reader)
        {
            var sb = new StringBuilder();
            while (true)
            {
                uint loaded = await reader.LoadAsync(1);
                if (loaded == 0)
                    return sb.ToString();

                byte b = reader.ReadByte();
                if (b == '\n')
                {
                    string line = sb.ToString();
                    if (line.EndsWith("\r"))
                        line = line.Substring(0, line.Length - 1);
                    return line;
                }
                sb.Append((char)b);
            }
        }
    }
}