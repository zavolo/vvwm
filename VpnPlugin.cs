using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace VlessVPN
{
    public class VpnPlugin : IVpnPlugIn
    {
        private VlessConfig _config;
        private CancellationTokenSource _cts;
        public event Action<string> Log;

        public void Connect(VpnChannel channel)
        {
            try
            {
                string uri = VlessConfig.LoadUri();
                if (string.IsNullOrEmpty(uri))
                {
                    channel.TerminateConnection("No VLESS configuration");
                    return;
                }

                _config = VlessConfig.Parse(uri);
                _cts = new CancellationTokenSource();

                var transport = new StreamSocket();
                transport.Control.KeepAlive = true;
                transport.Control.NoDelay = true;

                if (_config.Security == "tls" || _config.Security == "reality")
                {
                    if (_config.Security == "reality")
                    {
                        transport.Control.IgnorableServerCertificateErrors.Add(
                            Windows.Security.Cryptography.Certificates.ChainValidationResult.Untrusted);
                        transport.Control.IgnorableServerCertificateErrors.Add(
                            Windows.Security.Cryptography.Certificates.ChainValidationResult.InvalidName);
                    }

                    transport.ConnectAsync(
                        new HostName(_config.Address),
                        _config.Port.ToString(),
                        SocketProtectionLevel.Tls12).AsTask().GetAwaiter().GetResult();
                }
                else
                {
                    transport.ConnectAsync(
                        new HostName(_config.Address),
                        _config.Port.ToString(),
                        SocketProtectionLevel.PlainSocket).AsTask().GetAwaiter().GetResult();
                }

                var routeScope = new VpnRouteAssignment();
                routeScope.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 0));
                routeScope.ExcludeLocalSubnets = true;

                var assignedIps = new VpnDomainNameAssignment();

                channel.AssociateTransport(transport, null);

                var localAddress = new HostName("10.233.233.2");
                channel.StartWithMainTransport(
                    new[] { localAddress },
                    null,
                    null,
                    routeScope,
                    assignedIps,
                    1400,
                    1500,
                    false,
                    transport
                );

                Log?.Invoke($"Connected to {_config.Address}:{_config.Port}");
            }
            catch (Exception ex)
            {
                channel.TerminateConnection(ex.Message);
                Log?.Invoke($"Connect error: {ex.Message}");
            }
        }

        public void Disconnect(VpnChannel channel)
        {
            try
            {
                _cts?.Cancel();
                channel.Stop();
                Log?.Invoke("Disconnected");
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Disconnect error: {ex.Message}");
            }
        }

        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            keepAlivePacket = null;
        }

        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets)
        {
            while (packets.Size > 0)
            {
                var packet = packets.RemoveAtBegin();
                encapsulatedPackets.Append(packet);
            }
        }

        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            decapsulatedPackets.Append(encapBuffer);
        }
    }
}