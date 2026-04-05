using System;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;

namespace VlessVPN
{
    public sealed partial class MainPage : Page
    {
        private SocksServer _socks;
        private HttpProxyServer _httpProxy;
        private bool _connected;
        private const int SocksPort = 1083;
        private const int HttpPort = 8080;

        public MainPage()
        {
            this.InitializeComponent();
            _connected = false;

            string savedUri = VlessConfig.LoadUri();
            if (!string.IsNullOrEmpty(savedUri))
            {
                UriBox.Text = savedUri;
                UpdateConfigInfo(savedUri);
            }
        }

        private async void PasteBtn_Click(object sender, RoutedEventArgs e)
        {
            var clipboard = Windows.ApplicationModel.DataTransfer.Clipboard.GetContent();
            if (clipboard.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.Text))
            {
                string text = await clipboard.GetTextAsync();
                if (!string.IsNullOrEmpty(text))
                {
                    UriBox.Text = text.Trim();
                }
            }
        }

        private async void FileBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FileOpenPicker();
                picker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
                picker.FileTypeFilter.Add(".txt");
                picker.FileTypeFilter.Add(".conf");
                picker.FileTypeFilter.Add(".vless");
                picker.FileTypeFilter.Add("*");

                StorageFile file = await picker.PickSingleFileAsync();
                if (file != null)
                {
                    string content = await FileIO.ReadTextAsync(file);
                    content = content.Trim();
                    string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string line in lines)
                    {
                        if (line.StartsWith("vless://"))
                        {
                            UriBox.Text = line.Trim();
                            AppendLog($"Loaded from {file.Name}");
                            return;
                        }
                    }
                    AppendLog($"No vless:// URI found in {file.Name}");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"File error: {ex.Message}");
            }
        }

        private async void ConnectBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_connected)
            {
                await DisconnectProxy();
            }
            else
            {
                await ConnectProxy();
            }
        }

        private async Task ConnectProxy()
        {
            string uri = UriBox.Text.Trim();
            if (string.IsNullOrEmpty(uri) || !uri.StartsWith("vless://"))
            {
                AppendLog("Invalid VLESS URI");
                return;
            }

            try
            {
                VlessConfig.SaveUri(uri);
                var config = VlessConfig.Parse(uri);
                UpdateConfigInfo(uri);

                SetStatus("Connecting...", "#FFFFA500");
                ConnectBtn.IsEnabled = false;
                AppendLog($"Connecting to {config.Address}:{config.Port}...");
                AppendLog($"Security: {config.Security}, Type: {config.Type}");

                _socks = new SocksServer();
                _socks.Log += (msg) =>
                {
                    var _ = Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () => AppendLog(msg));
                };

                await _socks.StartAsync(config, SocksPort);

                _httpProxy = new HttpProxyServer();
                _httpProxy.Log += (msg) =>
                {
                    var _ = Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () => AppendLog(msg));
                };
                await _httpProxy.StartAsync(config, HttpPort);

                _connected = true;
                SetStatus($"HTTP proxy 127.0.0.1:{HttpPort}", "#FF4CAF50");
                ConnectBtn.Content = "DISCONNECT";
                ConnectBtn.Background = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 244, 67, 54));
                AppendLog($"HTTP proxy: 127.0.0.1:{HttpPort}");
                AppendLog($"SOCKS5 proxy: 127.0.0.1:{SocksPort}");
            }
            catch (Exception ex)
            {
                SetStatus("Error", "#FFFF0000");
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                ConnectBtn.IsEnabled = true;
            }
        }

        private async Task DisconnectProxy()
        {
            try
            {
                ConnectBtn.IsEnabled = false;
                _socks?.Stop();
                _socks = null;
                _httpProxy?.Stop();
                _httpProxy = null;

                _connected = false;
                SetStatus("Disconnected", "#FF888888");
                ConnectBtn.Content = "CONNECT";
                ConnectBtn.Background = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 76, 175, 80));
            }
            catch (Exception ex)
            {
                AppendLog($"Disconnect error: {ex.Message}");
            }
            finally
            {
                ConnectBtn.IsEnabled = true;
            }
        }

        private void UpdateConfigInfo(string uri)
        {
            try
            {
                var cfg = VlessConfig.Parse(uri);
                ConfigInfo.Text = $"{cfg.Address}:{cfg.Port} | {cfg.Security} | {cfg.Type}";
            }
            catch
            {
                ConfigInfo.Text = "";
            }
        }

        private void SetStatus(string text, string color)
        {
            StatusText.Text = text;
            StatusText.Foreground = new SolidColorBrush(ParseColor(color));
        }

        private void AppendLog(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            LogBox.Text += $"[{timestamp}] {message}\r\n";
            LogBox.Select(LogBox.Text.Length, 0);
        }

        private static Windows.UI.Color ParseColor(string hex)
        {
            hex = hex.Replace("#", "");
            byte a = Convert.ToByte(hex.Substring(0, 2), 16);
            byte r = Convert.ToByte(hex.Substring(2, 2), 16);
            byte g = Convert.ToByte(hex.Substring(4, 2), 16);
            byte b = Convert.ToByte(hex.Substring(6, 2), 16);
            return Windows.UI.Color.FromArgb(a, r, g, b);
        }
    }
}