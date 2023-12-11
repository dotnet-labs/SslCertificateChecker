using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace SslCertificateChecker;

public interface ICertificateChecker
{
    Task Check(string url);
    Task<DateTime> GetExpirationDate(string url);
}

public class CertificateChecker(HttpClient httpClient, CertificateHttpClientHandler clientHandler)
    : ICertificateChecker
{
    public async Task Check(string url)
    {
        try
        {
            var uri = new Uri(url);
            _ = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, uri));
            var certificate = clientHandler.GetCertificate(uri);
            if (certificate == null)
            {
                Console.WriteLine($"Certificate Not Found for the site {url}");
                return;
            }
            Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            Console.WriteLine($"Exp date: {DateTime.Parse(certificate.GetExpirationDateString())}");
            Console.WriteLine($"Issuer: {certificate.Issuer}");
            Console.WriteLine($"Subject: {certificate.Subject}");

        }
        catch (HttpRequestException e)
        {
            Console.WriteLine("\nException Caught!");
            Console.WriteLine($"Message: {e.Message} ");
        }
    }
    public async Task<DateTime> GetExpirationDate(string url)
    {
        try
        {
            var uri = new Uri(url.Contains("://") ? url : "https://" + url);
            _ = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, uri));
            var certificate = clientHandler.GetCertificate(uri);
            return certificate == default ? DateTime.MinValue : DateTime.Parse(certificate.GetExpirationDateString());
        }
        catch
        {
            return DateTime.MinValue;
        }
    }
}

public class CertificateHttpClientHandler : HttpClientHandler
{
    private readonly ConcurrentDictionary<Uri, X509Certificate2> _certificates = new();

    public CertificateHttpClientHandler(ProxySettings proxySettings)
    {
        if (!string.IsNullOrWhiteSpace(proxySettings.Address))
        {
            Proxy = new WebProxy($"{proxySettings.Address}:{proxySettings.Port}", true);
        }

        ServerCertificateCustomValidationCallback = (requestMessage, certificate, _, sslErrors) =>
        {
            if (requestMessage.RequestUri == null || certificate == null)
            {
                return false;
            }

            _certificates.AddOrUpdate(requestMessage.RequestUri, _ => certificate, (_, _) => certificate);
            // It is possible inspect the certificate provided by server
            Console.WriteLine($"Requested URI: {requestMessage.RequestUri}");

            // Based on the custom logic it is possible to decide whether the client considers certificate valid or not
            Console.WriteLine($"Errors: {sslErrors}");
            return sslErrors == SslPolicyErrors.None;
        };
    }

    public X509Certificate2? GetCertificate(Uri uri)
    {
        return _certificates.GetValueOrDefault(uri);
    }
}

public record ProxySettings(string Address = "", int Port = 0);