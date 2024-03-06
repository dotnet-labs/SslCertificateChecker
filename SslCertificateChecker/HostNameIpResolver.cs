using System.Net;
using System.Net.Sockets;

namespace SslCertificateChecker;

internal class IpResolver
{
    // A host can have multiple IP addresses!
    public static IPAddress[] GetIPsByHostName(string hostName, IpType ipType = IpType.Both)
    {
        hostName = hostName.Trim('/');
        hostName = hostName[(hostName.LastIndexOf('/') + 1)..];

        // Check if the hostname is already an IPAddress
        if (IPAddress.TryParse(hostName, out var outIpAddress)) return [outIpAddress];

        try
        {
            var addresses = Dns.GetHostAddresses(hostName);
            if (addresses.Length == 0) return [];

            return ipType switch
            {
                IpType.Both => addresses,
                IpType.IpV4 => addresses.Where(o => o.AddressFamily == AddressFamily.InterNetwork).ToArray(),
                IpType.IpV6 => addresses.Where(o => o.AddressFamily == AddressFamily.InterNetworkV6).ToArray(),
                _ => []
            };
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return [];
        }


    }
}

public enum IpType
{
    None = 0,
    IpV4 = 1,
    IpV6 = 2,
    Both = 3,
}