// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace DepotDownloader
{
    public static class ListDepotsCommand
    {
        public static int PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("List Depots - Display branches per depot from a CSV");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader list-depots <manifest.csv>");
            Console.WriteLine();
            Console.WriteLine("DESCRIPTION:");
            Console.WriteLine("  Reads a CSV file (AppID,DepotID,ManifestID,Branch,Release Date) and prints");
            Console.WriteLine("  a list of branch names for each depot found. No Steam login or downloads occur.");
            Console.WriteLine();
            Console.WriteLine("OPTIONS:");
            // Retained for potential future expansion; currently unused:
            // Console.WriteLine("  -manifest-csv <file>   Path to the CSV containing manifest rows");
            Console.WriteLine();
            Console.WriteLine("OUTPUT:");
            Console.WriteLine("  Grouped by DepotID; within each depot, branches are distinct and sorted by name.");
            Console.WriteLine();
            return 0;
        }

        public static int PrintErrorAndUsage(string message)
        {
            Console.WriteLine("Error: " + message);
            return PrintUsage();
        }

        public static int RunSync(string[] args)
        {
            var parser = new ArgParser(args);

            if (args.Length == 0 || parser.HasFlag("-h", "--help", "help"))
            {
                return PrintUsage();
            }

            // Positional CSV argument (preferred)
            var csvPath = parser.Positional(0);

            if (string.IsNullOrWhiteSpace(csvPath))
            {
                return PrintErrorAndUsage("Missing CSV path. Usage: depotdownloader list-depots <manifest.csv>");
            }

            if (!File.Exists(csvPath))
            {
                Console.WriteLine($"Error: CSV file not found: {csvPath}");
                return 1;
            }

            var rows = ReadManifestCsvBasic(csvPath).ToList();
            if (rows.Count == 0)
            {
                Console.WriteLine("No valid rows found in CSV.");
                return 0;
            }

            PrintBranchTable(rows);
            return 0;
        }

        public static System.Threading.Tasks.Task<int> RunAsync(string[] args)
            => System.Threading.Tasks.Task.FromResult(RunSync(args));

        private static IEnumerable<(uint DepotID, string Branch)> ReadManifestCsvBasic(string path)
        {
            using var reader = new StreamReader(File.OpenRead(path));

            string line;
            bool headerSkipped = false;

            while ((line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                if (!headerSkipped)
                {
                    headerSkipped = true;
                    // Skip header if present
                    if (line.StartsWith("AppID,DepotID,ManifestID", StringComparison.OrdinalIgnoreCase))
                        continue;
                }

                var parts = line.Split(',');
                if (parts.Length < 4)
                    continue;

                // AppID parts[0] is not required here
                if (!uint.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var depotId))
                    continue;

                var branch = parts[3].Trim();
                if (string.IsNullOrWhiteSpace(branch))
                {
                    branch = ContentDownloader.DEFAULT_BRANCH;
                }

                yield return (depotId, branch);
            }
        }

        private static void PrintBranchTable(IEnumerable<(uint DepotID, string Branch)> rows)
        {
            var groups = rows
                .GroupBy(r => r.DepotID)
                .OrderBy(g => g.Key)
                .ToList();

            Console.WriteLine();
            Console.WriteLine("Branches by Depot (grouped by DepotID):");
            Console.WriteLine();

            if (groups.Count == 0)
            {
                Console.WriteLine("No depots found.");
                return;
            }

            foreach (var grp in groups)
            {
                var depotId = grp.Key;
                var branches = grp
                    .Select(x => x.Branch)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                Console.WriteLine($"Depot {depotId}:");
                foreach (var b in branches)
                {
                    Console.WriteLine($"  - {b}");
                }
                Console.WriteLine();
            }
        }
    }
}
