using SslCertificateChecker;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        services.AddSingleton<CertificateHttpClientHandler>();
        services.AddHttpClient<ICertificateChecker, CertificateChecker>()
            .ConfigurePrimaryHttpMessageHandler(sp => sp.GetRequiredService<CertificateHttpClientHandler>());
        services.AddHostedService<Worker>();
    })
    .Build();

await host.RunAsync();
