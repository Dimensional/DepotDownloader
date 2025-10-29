// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace DepotDownloader
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintVersion();
                PrintUsage();

                if (OperatingSystem.IsWindowsVersionAtLeast(5, 0))
                {
                    PlatformUtilities.VerifyConsoleLaunch();
                }

                return 0;
            }

            Ansi.Init();
            DebugLog.Enabled = false;

            // Check if this is a sub-command
            if (args.Length > 0)
            {
                var firstArg = args[0].ToLowerInvariant();

                switch (firstArg)
                {
                    case "download":
                        return await DownloadCommand.RunAsync(args[1..]);

                    case "list-depots": // NEW
                        return await ListDepotsCommand.RunAsync(args[1..]);

                    case "validate-depot":
                    case "validate-chunk":
                    case "validate-chunkstore":
                    case "validate-chunkstore-chunks":
                        return await ChunkValidatorProgram.RunChunkValidationAsync(args);

                    case "reconstruct":
                        return await ReconstructCommand.RunAsync(args[1..]);

                    case "chunkstore":
                        return await ChunkstoreCommand.RunAsync(args[1..]);

                    case "help":
                    case "--help":
                    case "-h":
                        if (args.Length > 1)
                        {
                            return PrintSubCommandHelp(args[1]);
                        }
                        PrintVersion();
                        PrintUsage();
                        return 0;

                    case "version":
                    case "--version":
                    case "-V":
                        PrintVersion(true);
                        return 0;
                }
            }

            // Legacy mode ...
            if (HasLegacyDownloadArgs(args))
            {
                Console.WriteLine("Warning: Using legacy argument format. Consider using the new 'download' sub-command:");
                Console.WriteLine($"  depotdownloader download {string.Join(" ", args)}");
                Console.WriteLine();

                return await DownloadCommand.RunLegacyAsync(args);
            }

            Console.WriteLine($"Unknown command: {args[0]}");
            Console.WriteLine("Use 'depotdownloader help' for usage information.");
            return 1;
        }

        private static bool HasLegacyDownloadArgs(string[] args)
        {
            // Check if args contain typical download parameters
            var downloadParams = new[] { "-app", "-manifest-csv", "-workshop", "-workshop-csv", "-username", "-depot" };
            return args.Any(arg => downloadParams.Contains(arg, StringComparer.OrdinalIgnoreCase));
        }

        private static int PrintSubCommandHelp(string subCommand)
        {
            switch (subCommand.ToLowerInvariant())
            {
                case "download":
                    DownloadCommand.PrintUsage();
                    return 0;

                case "list-depots": // NEW
                    ListDepotsCommand.PrintUsage();
                    return 0;

                case "validate-depot":
                case "validate-chunk":
                case "validate-chunkstore":
                case "validate-chunkstore-chunks":
                case "validation":
                    ChunkValidatorProgram.PrintValidationHelp();
                    return 0;

                case "reconstruct":
                    ReconstructCommand.PrintUsage();
                    return 0;

                case "chunkstore":
                    ChunkstoreCommand.PrintUsage();
                    return 0;

                default:
                    Console.WriteLine($"Unknown sub-command: {subCommand}");
                    Console.WriteLine("Available sub-commands: download, list-depots, validation, reconstruct, chunkstore");
                    return 1;
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("DepotDownloader - Steam Content Download and Management Tool");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader <COMMAND> [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("COMMANDS:");
            Console.WriteLine("  download                     Download Steam content (apps, depots, workshop items)");
            Console.WriteLine("  list-depots                  List branches per depot from a CSV (no download)"); // NEW
            Console.WriteLine("  validate-depot               Validate all chunks in a depot directory (offline)");
            Console.WriteLine("  validate-chunk               Validate a single chunk file (offline)");
            Console.WriteLine("  validate-chunkstore          Validate all chunks in a chunkstore (offline)");
            Console.WriteLine("  validate-chunkstore-chunks   Validate specific chunks in a chunkstore (offline)");
            Console.WriteLine("  reconstruct                  Process raw chunks into installed files [Coming Soon]");
            Console.WriteLine("  chunkstore                   Manage chunk storage and deduplication [Coming Soon]");
            Console.WriteLine();
            Console.WriteLine("HELP:");
            Console.WriteLine("  help              Show this help message");
            Console.WriteLine("  help <command>    Show help for a specific command");
            Console.WriteLine("  version           Show version information");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  depotdownloader download -app 4000 -depot 4001 -raw");
            Console.WriteLine("  depotdownloader list-depots -manifest-csv manifests.csv"); // NEW example
            Console.WriteLine("  depotdownloader validate-depot depot/4001 -verbose");
            Console.WriteLine("  depotdownloader download -workshop 123456 789012");
            Console.WriteLine();
            Console.WriteLine("For detailed help on any command: depotdownloader help <command>");
            Console.WriteLine();
            Console.WriteLine("LEGACY COMPATIBILITY:");
            Console.WriteLine("  The old argument format (without sub-commands) is still supported but deprecated.");
            Console.WriteLine("  Consider migrating to the new sub-command format for future compatibility.");
        }

        static void PrintVersion(bool printExtra = false)
        {
            var version = typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion;
            Console.WriteLine($"DepotDownloader v{version}");

            if (!printExtra)
            {
                return;
            }

            Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription} on {RuntimeInformation.OSDescription}");
        }
    }
}
