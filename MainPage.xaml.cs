using System;
using System.Threading.Tasks;
using Windows.ApplicationModel.Core;
using Windows.Networking;
using Windows.Networking.Vpn;
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
        private VpnManagementAgent _vpnAgent;
        private VpnPlugInProfile _vpnProfile;
        private bool _connected;
        private const string ProfileName = "VlessVPN";

        public MainPage()
        {
            this.InitializeComponent();
            _vpnAgent = new VpnManagementAgent();
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
                    if (content.StartsWith("vless://"))
                    {
                        UriBox.Text = content;
                        AppendLog($"Loaded from {file.Name}");
                    }
                    else
                    {
                        AppendLog($"No vless:// URI found in {file.Name}");
                    }
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
                await DisconnectVpn();
            }
            else
            {
                await ConnectVpn();
            }
        }

        private async Task ConnectVpn()
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

                await RemoveExistingProfile();

                _vpnProfile = new VpnPlugInProfile
                {
                    ProfileName = ProfileName,
                    RequireVpnClientAppUI = true,
                    AlwaysOn = false
                };
                _vpnProfile.VpnPluginPackageFamilyName = Windows.ApplicationModel.Package.Current.Id.FamilyName;
                _vpnProfile.ServerUris.Add(new Uri($"https://{config.Address}:{config.Port}"));

                var addResult = await _vpnAgent.AddProfileFromObjectAsync(_vpnProfile);
                AppendLog($"Profile add: {addResult}");

                if (addResult != VpnManagementErrorStatus.Ok)
                {
                    SetStatus("Profile error", "#FFFF0000");
                    ConnectBtn.IsEnabled = true;
                    return;
                }

                var connectResult = await _vpnAgent.ConnectProfileAsync(_vpnProfile);
                AppendLog($"Connect result: {connectResult}");

                if (connectResult == VpnManagementErrorStatus.Ok)
                {
                    _connected = true;
                    SetStatus("Connected", "#FF4CAF50");
                    ConnectBtn.Content = "DISCONNECT";
                    ConnectBtn.Background = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 244, 67, 54));
                }
                else
                {
                    SetStatus("Connection failed", "#FFFF0000");
                    AppendLog($"Error: {connectResult}");
                }
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

        private async Task DisconnectVpn()
        {
            try
            {
                ConnectBtn.IsEnabled = false;
                SetStatus("Disconnecting...", "#FFFFA500");

                if (_vpnProfile != null)
                {
                    var result = await _vpnAgent.DisconnectProfileAsync(_vpnProfile);
                    AppendLog($"Disconnect: {result}");
                    await _vpnAgent.DeleteProfileAsync(_vpnProfile);
                }

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

        private async Task RemoveExistingProfile()
        {
            var profiles = await _vpnAgent.GetProfilesAsync();
            foreach (var p in profiles)
            {
                if (p.ProfileName == ProfileName)
                {
                    await _vpnAgent.DeleteProfileAsync(p);
                }
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