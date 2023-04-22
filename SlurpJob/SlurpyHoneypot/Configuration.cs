using SlurpyHoneypot;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace SlurpyHoneypot
{
    public class Configuration
    {
        private readonly IConfiguration _configuration;

        public Configuration()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

            _configuration = builder.Build();
        }

        public T GetSetting<T>(string settingName)
        {
            return _configuration.GetValue<T>(settingName);
        }
    }
}
