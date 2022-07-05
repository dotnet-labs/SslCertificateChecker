using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace SslCertificateChecker
{
    public interface ICertificateChecker
    {
        Task Check(string url);
    }

    public class CertificateChecker : ICertificateChecker
    {
        private readonly HttpClient _httpClient;
        private readonly CertificateHttpClientHandler _clientHandler;
        public CertificateChecker(HttpClient httpClient, CertificateHttpClientHandler clientHandler)
        {
            _httpClient = httpClient;
            _clientHandler = clientHandler;
        }

        public async Task Check(string url)
        {
            try
            {
                var uri = new Uri(url);
                var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, uri));
                response.EnsureSuccessStatusCode();
                var certificate = _clientHandler.GetCertificate(uri);
                if (certificate == null)
                {
                    Console.WriteLine($"Certificate Not Found for the site {url}");
                    return;
                }
                Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
                Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
                Console.WriteLine($"Issuer: {certificate.Issuer}");
                Console.WriteLine($"Subject: {certificate.Subject}");

            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine($"Message: {e.Message} ");
            }
        }
    }

    public class CertificateHttpClientHandler : HttpClientHandler
    {
        private readonly ConcurrentDictionary<Uri, X509Certificate2> _certificates = new();

        public CertificateHttpClientHandler()
        {
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
}
