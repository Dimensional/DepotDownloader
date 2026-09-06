// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.IO;
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
            // Titles/paths routinely contain non-Latin scripts (workshop items are published from
            // every region) - .NET strings and protobuf-net's wire format already carry these
            // correctly regardless of this setting (confirmed: neither the catalog's serialized
            // strings nor Path.GetInvalidFileNameChars()-based filename sanitization ever touch
            // valid Unicode characters), but Console.Out defaults to the OS's legacy console code
            // page on Windows, which can't represent most of them - anything outside it gets
            // silently replaced with '?' purely for display, not stored that way.
            //
            // Windows-only: non-Windows terminals already default to UTF-8, so this would be a
            // no-op there anyway, and narrowing it to where it's actually needed avoids touching a
            // working default on a platform this wasn't tested against. A comparable project in
            // this same space (steam-lancache-prefill) documents this exact issue but deliberately
            // does NOT set it programmatically - it tells users to switch to Windows Terminal and
            // opt in themselves (see their Linux/Windows setup docs) - because their output is a
            // Spectre.Console TUI (live progress bars/animations) that a font/encoding mismatch on
            // a legacy console can visibly break. This project's workshop output is plain
            // sequential Console.WriteLine text with no such rendering to protect: on a legacy
            // raster-font console that can't render a given glyph, the worst case is a tofu/box
            // per character (same "can't show this glyph" outcome either way) instead of '?' - not
            // a regression - while every modern host (Windows Terminal, VS Code, PowerShell 7,
            // redirected output/log files) gets it right automatically instead of needing a manual
            // opt-in step. Best-effort: some hosts (certain redirected pipes) reject setting this,
            // and that's not worth failing startup over.
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    Console.OutputEncoding = System.Text.Encoding.UTF8;
                }
                catch (IOException)
                {
                }
            }

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

                    case "manifest":
                        return await ManifestCommand.RunAsync(args[1..]);

                    case "validate-depot":
                    case "validate-chunk":
                    case "validate-chunkstore":
                    case "validate-chunkstore-chunks":
                        return await ChunkValidatorProgram.RunChunkValidationAsync(args);

                    case "reconstruct":
                        return await ReconstructCommand.RunAsync(args[1..]);

                    case "chunkstore":
                        return await ChunkstoreCommand.RunAsync(args[1..]);

                    case "workshop":
                        return await WorkshopCommand.RunAsync(args[1..]);

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
                    case "-v":
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
            // -workshop/-workshop-csv are kept here even though "download" no longer accepts them -
            // this only decides whether legacy (no-subcommand) syntax gets routed into
            // DownloadCommand, which then prints the "moved to workshop command" redirect message.
            // Without this, e.g. "depotdownloader -workshop 123" would fall through to a bare
            // "Unknown command: -workshop" instead of that more useful redirect.
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

                case "manifest":
                    ManifestCommand.PrintUsage();
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

                case "workshop":
                    WorkshopCommand.PrintUsage();
                    return 0;

                default:
                    Console.WriteLine($"Unknown sub-command: {subCommand}");
                    Console.WriteLine("Available sub-commands: download, list-depots, manifest, validation, reconstruct, chunkstore, workshop");
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
            Console.WriteLine("  download                     Download Steam content (apps, depots)");
            Console.WriteLine("  list-depots                  List branches per depot from a CSV (no download)"); // NEW
            Console.WriteLine("  manifest                     Extract, compare, and list manifest files (offline)");
            Console.WriteLine("  validate-depot               Validate all chunks in a depot directory (offline)");
            Console.WriteLine("  validate-chunk               Validate a single chunk file (offline)");
            Console.WriteLine("  validate-chunkstore          Validate all chunks in a chunkstore (offline; alias for 'chunkstore verify')");
            Console.WriteLine("  validate-chunkstore-chunks   Validate specific chunks in a chunkstore (offline; alias for 'chunkstore verify -chunks')");
            Console.WriteLine("  reconstruct                  Rebuild installed files offline from a manifest + archived chunks");
            Console.WriteLine("  chunkstore                   Pack/unpack/verify/stats/update/rebuild on chunk storage");
            Console.WriteLine("  workshop                     Bootstrap/poll an app's whole workshop (chunk-based + ancient UGC) for automatic update tracking");
            Console.WriteLine();
            Console.WriteLine("HELP:");
            Console.WriteLine("  help              Show this help message");
            Console.WriteLine("  help <command>    Show help for a specific command");
            Console.WriteLine("  version           Show version information");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  depotdownloader download -app 4000 -depot 4001 -raw");
            Console.WriteLine("  depotdownloader list-depots -manifest-csv manifests.csv");
            Console.WriteLine("  depotdownloader manifest extract 123456.manif5 -depot 848452");
            Console.WriteLine("  depotdownloader manifest diff old.json new.json -verbose");
            Console.WriteLine("  depotdownloader manifest list -depot 4000 -workshop");
            Console.WriteLine("  depotdownloader validate-depot depot/4001 -verbose");
            Console.WriteLine("  depotdownloader workshop download -workshop 123456 789012");
            Console.WriteLine("  depotdownloader workshop bootstrap -app 4000");
            Console.WriteLine("  depotdownloader workshop poll -app 4000 -username myaccount -remember-password");
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
