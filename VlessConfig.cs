using System;
using System.Collections.Generic;
using Windows.Storage;

namespace VlessVPN
{
    public class VlessConfig
    {
        public string Uuid { get; set; }
        public string Address { get; set; }
        public int Port { get; set; }
        public string Encryption { get; set; } = "none";
        public string Flow { get; set; } = "";
        public string Type { get; set; } = "tcp";
        public string Security { get; set; } = "none";
        public string Sni { get; set; } = "";
        public string Fp { get; set; } = "";
        public string Pbk { get; set; } = "";
        public string Sid { get; set; } = "";
        public string Path { get; set; } = "";
        public string Host { get; set; } = "";
        public string Mode { get; set; } = "";
        public string Remark { get; set; } = "";

        public static VlessConfig Parse(string uri)
        {
            if (!uri.StartsWith("vless://"))
                throw new ArgumentException("Invalid VLESS URI");

            uri = uri.Substring(8);

            int atIdx = uri.IndexOf('@');
            if (atIdx < 0) throw new ArgumentException("Invalid VLESS URI");

            string uuid = uri.Substring(0, atIdx);
            string rest = uri.Substring(atIdx + 1);

            string remark = "";
            int hashIdx = rest.IndexOf('#');
            if (hashIdx >= 0)
            {
                remark = Uri.UnescapeDataString(rest.Substring(hashIdx + 1));
                rest = rest.Substring(0, hashIdx);
            }

            string hostPort;
            var parameters = new Dictionary<string, string>();
            int qIdx = rest.IndexOf('?');
            if (qIdx >= 0)
            {
                hostPort = rest.Substring(0, qIdx);
                string queryStr = rest.Substring(qIdx + 1);
                foreach (string pair in queryStr.Split('&'))
                {
                    int eqIdx = pair.IndexOf('=');
                    if (eqIdx > 0)
                    {
                        string key = Uri.UnescapeDataString(pair.Substring(0, eqIdx));
                        string val = Uri.UnescapeDataString(pair.Substring(eqIdx + 1));
                        parameters[key] = val;
                    }
                }
            }
            else
            {
                hostPort = rest;
            }

            string address;
            int port;
            if (hostPort.StartsWith("["))
            {
                int bracketEnd = hostPort.IndexOf(']');
                address = hostPort.Substring(1, bracketEnd - 1);
                port = int.Parse(hostPort.Substring(bracketEnd + 2));
            }
            else
            {
                int colonIdx = hostPort.LastIndexOf(':');
                address = hostPort.Substring(0, colonIdx);
                port = int.Parse(hostPort.Substring(colonIdx + 1));
            }

            var cfg = new VlessConfig
            {
                Uuid = uuid,
                Address = address,
                Port = port,
                Remark = remark
            };

            if (parameters.ContainsKey("encryption")) cfg.Encryption = parameters["encryption"];
            if (parameters.ContainsKey("flow")) cfg.Flow = parameters["flow"];
            if (parameters.ContainsKey("type")) cfg.Type = parameters["type"];
            if (parameters.ContainsKey("security")) cfg.Security = parameters["security"];
            if (parameters.ContainsKey("sni")) cfg.Sni = parameters["sni"];
            if (parameters.ContainsKey("fp")) cfg.Fp = parameters["fp"];
            if (parameters.ContainsKey("pbk")) cfg.Pbk = parameters["pbk"];
            if (parameters.ContainsKey("sid")) cfg.Sid = parameters["sid"];
            if (parameters.ContainsKey("path")) cfg.Path = parameters["path"];
            if (parameters.ContainsKey("host")) cfg.Host = parameters["host"];
            if (parameters.ContainsKey("mode")) cfg.Mode = parameters["mode"];

            return cfg;
        }

        public string ToUri()
        {
            string query = $"encryption={Encryption}&type={Type}&security={Security}";
            if (!string.IsNullOrEmpty(Flow)) query += $"&flow={Flow}";
            if (!string.IsNullOrEmpty(Sni)) query += $"&sni={Sni}";
            if (!string.IsNullOrEmpty(Fp)) query += $"&fp={Fp}";
            if (!string.IsNullOrEmpty(Pbk)) query += $"&pbk={Pbk}";
            if (!string.IsNullOrEmpty(Sid)) query += $"&sid={Sid}";
            if (!string.IsNullOrEmpty(Path)) query += $"&path={Uri.EscapeDataString(Path)}";
            if (!string.IsNullOrEmpty(Host)) query += $"&host={Host}";
            if (!string.IsNullOrEmpty(Mode)) query += $"&mode={Mode}";
            string remarkPart = string.IsNullOrEmpty(Remark) ? "" : "#" + Uri.EscapeDataString(Remark);
            return $"vless://{Uuid}@{Address}:{Port}?{query}{remarkPart}";
        }

        public override string ToString()
        {
            return string.IsNullOrEmpty(Remark) ? $"{Address}:{Port}" : Remark;
        }

        public static void SaveUri(string uri)
        {
            ApplicationData.Current.LocalSettings.Values["vless_uri"] = uri;
        }

        public static string LoadUri()
        {
            if (ApplicationData.Current.LocalSettings.Values.ContainsKey("vless_uri"))
                return ApplicationData.Current.LocalSettings.Values["vless_uri"] as string;
            return null;
        }
    }
}