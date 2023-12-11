namespace SslCertificateChecker;

public class Worker(ICertificateChecker certificateChecker, ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        const string url = "https://docs.microsoft.com/";
        await certificateChecker.Check(url);
        var d = await certificateChecker.GetExpirationDate(url);
        logger.LogInformation("SSL Certificate for [{url}] expires At: {d}", url, d);
    }
}