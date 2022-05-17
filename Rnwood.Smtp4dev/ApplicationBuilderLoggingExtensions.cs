using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Rnwood.Smtp4dev
{

    public static class ApplicationBuilderLoggingExtensions
    {

        public static void LogServerInformation(this IApplicationBuilder app, LogLevel logLevel = LogLevel.Debug)
        {
            var logger = app.ApplicationServices.GetRequiredService<ILogger<Startup>>();
            if (!logger.IsEnabled(logLevel))
                return;

            var env = app.ApplicationServices.GetRequiredService<IWebHostEnvironment>();
            logger.Log(logLevel, "Application informations:");
            logger.Log(logLevel, "Version: {Version}", Assembly.GetCallingAssembly().GetName().Version);
            logger.Log(logLevel, "EnvironmentName: {EnvironmentName}", env.EnvironmentName);
            logger.Log(logLevel, "ApplicationName: {ApplicationName}", env.ApplicationName);
            logger.Log(logLevel, "ContentRootPath: {ContentRootPath}", env.ContentRootPath);
            logger.Log(logLevel, "WebRootPath: {WebRootPath}", env.WebRootPath);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                logger.Log(logLevel, "Application runs under user: {WindowsUserName}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            }
            var server = app.ApplicationServices.GetService<Microsoft.AspNetCore.Hosting.Server.IServer>();
            if (server != null)
            {
                foreach (var feature in server.Features)
                {
                    logger.Log(logLevel, "Found Feature: {FeatureName}", feature.Key.FullName);
                    if (feature.Value is Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature sa)
                    {
                        logger.Log(logLevel, "ServerAddresses.PreferHostingUrls: {ServerAddresses_PreferHostingUrls}", sa.PreferHostingUrls);
                        foreach (var address in sa.Addresses)
                        {
                            logger.Log(logLevel, "ServerAddresses.Address: {ServerAddresses_Address}", address);
                        }
                    }
                }
            }
            logger.Log(logLevel, "Configurations:");
            var configuration = app.ApplicationServices.GetRequiredService<IConfiguration>();
            foreach (var item in configuration.AsEnumerable())
            {

                var value = HidePasswords(item.Key, item.Value);
                logger.Log(logLevel, "Entry {key}: {value}", item.Key, value);
            }
            logger.Log(logLevel, "Configurations End.");
            var providers = (configuration as IConfigurationRoot)?.Providers;
            if (providers != null)
            {
                logger.Log(logLevel, "Configuration Providers:");
                foreach (var item in providers)
                {
                    logger.Log(logLevel, "Configuration Provider: {ConfigurationProvider}", item.GetType().Name);
                    switch (item)
                    {
                        case JsonConfigurationProvider json:
                            var fileInfo = json.Source.FileProvider.GetFileInfo(json.Source.Path);
                            logger.Log(logLevel, "Json Source Path: {SourcePath} {Exists}",
                                fileInfo.PhysicalPath ?? fileInfo.Name,
                                fileInfo.Exists ? "Exists" : "");
                            break;
                        default:
                            break;
                    }
                }
                logger.Log(logLevel, "Configuration Provider End.");
            }
            else
            {
                logger.Log(logLevel, "Requested service IConfiguration is not IConfigurationRoot.");
            }
        }

        private static string HidePasswords(string key, string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }
            if (ContainsIgnoreCase(key, "password"))
                return "<hidden>";
            if (ContainsIgnoreCase(key, "secret"))
                return "<hidden>";
            return _passwordReplace.Replace(value, "password=<hidden>");
        }

        private static readonly Regex _passwordReplace = new Regex(@"password=.*(;|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static bool ContainsIgnoreCase(string text, string value)
        {
            return text.IndexOf(value, StringComparison.OrdinalIgnoreCase) > -1;
        }

        public class Startup
        {

        }
    }
}