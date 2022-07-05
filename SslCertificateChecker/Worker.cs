namespace SslCertificateChecker
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly ICertificateChecker _certificateChecker;

        public Worker(ILogger<Worker> logger, ICertificateChecker certificateChecker)
        {
            _logger = logger;
            _certificateChecker = certificateChecker;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await _certificateChecker.Check("https://docs.microsoft.com/");
        }
    }
}