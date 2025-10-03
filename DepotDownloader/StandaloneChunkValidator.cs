// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    /// <summary>
    /// Standalone tool for validating depot chunks without requiring Steam connection
    /// </summary>
    public static class StandaloneChunkValidator
    {
        /// <summary>
        /// Validate all chunks in a depot directory structure
        /// </summary>
        /// <param name="depotPath">Path to depot directory (e.g., "depot/12345")</param>
        /// <param name="manifestPath">Optional path to manifest file (currently unused - size detection is automatic)</param>
        /// <param name="verbose">Show detailed output for each chunk</param>
        /// <returns>Validation summary</returns>
        public static async Task<ValidationSummary> ValidateDepotChunksAsync(string depotPath, string manifestPath = null, bool verbose = false)
        {
            var summary = new ValidationSummary();

            if (!Directory.Exists(depotPath))
            {
                Console.WriteLine($"Error: Depot directory not found: {depotPath}");
                return summary;
            }

            // Look for depot key
            var depotKeyPath = Directory.GetFiles(depotPath, "*.depotkey").FirstOrDefault();
            if (depotKeyPath == null)
            {
                Console.WriteLine($"Error: No depot key found in {depotPath}");
                return summary;
            }

            var depotKey = await File.ReadAllBytesAsync(depotKeyPath);
            Console.WriteLine($"Using depot key: {Path.GetFileName(depotKeyPath)}");

            // Look for chunks directory
            var chunksDir = Path.Combine(depotPath, "chunk");
            if (!Directory.Exists(chunksDir))
            {
                Console.WriteLine($"Error: Chunks directory not found: {chunksDir}");
                return summary;
            }

            // Note about manifest parameter
            if (!string.IsNullOrEmpty(manifestPath))
            {
                Console.WriteLine($"Note: Manifest parameter provided but not used - chunk sizes are auto-detected");
            }

            // Find all chunk files
            var chunkFiles = Directory.GetFiles(chunksDir, "*", SearchOption.TopDirectoryOnly)
                                     .Where(f => !Path.HasExtension(f)) // Chunk files have no extension
                                     .ToList();

            summary.TotalChunks = chunkFiles.Count;
            Console.WriteLine($"Found {chunkFiles.Count} chunk files to validate");

            // Validate each chunk using dynamic size detection
            foreach (var chunkFile in chunkFiles)
            {
                var chunkId = Path.GetFileName(chunkFile);

                try
                {
                    // Use dynamic size detection (estimatedUncompressedLength parameter is ignored)
                    var result = await ChunkValidator.ValidateRawChunkAsync(chunkFile, depotKey, 0);

                    if (result.IsValid)
                    {
                        summary.ValidChunks++;
                        if (verbose)
                        {
                            Console.WriteLine($"✓ {chunkId} - Valid ({result.DecompressedSize} bytes)");
                        }
                    }
                    else
                    {
                        summary.InvalidChunks++;
                        Console.WriteLine($"✗ {chunkId} - {result.ErrorMessage}");
                    }
                }
                catch (Exception ex)
                {
                    summary.ErrorChunks++;
                    Console.WriteLine($"✗ {chunkId} - Error: {ex.Message}");
                }
            }

            return summary;
        }

        /// <summary>
        /// Validate a single chunk file
        /// </summary>
        /// <param name="chunkFilePath">Path to chunk file</param>
        /// <param name="depotKeyPath">Path to depot key file</param>
        /// <param name="uncompressedLength">Expected uncompressed length (ignored - size is auto-detected)</param>
        /// <returns>Validation result</returns>
        public static async Task<ValidationResult> ValidateSingleChunkAsync(string chunkFilePath, string depotKeyPath, uint uncompressedLength = 0)
        {
            if (!File.Exists(depotKeyPath))
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Depot key file not found: {depotKeyPath}"
                };
            }

            var depotKey = await File.ReadAllBytesAsync(depotKeyPath);

            // Use dynamic size detection (uncompressedLength parameter is ignored)
            return await ChunkValidator.ValidateRawChunkAsync(chunkFilePath, depotKey, 0);
        }
    }

    /// <summary>
    /// Summary of chunk validation results
    /// </summary>
    public class ValidationSummary
    {
        public int TotalChunks { get; set; }
        public int ValidChunks { get; set; }
        public int InvalidChunks { get; set; }
        public int ErrorChunks { get; set; }

        public double ValidPercentage => TotalChunks > 0 ? (ValidChunks / (double)TotalChunks) * 100.0 : 0.0;

        public override string ToString()
        {
            return $"Validation Summary: {ValidChunks}/{TotalChunks} valid ({ValidPercentage:F1}%), " +
                   $"{InvalidChunks} invalid, {ErrorChunks} errors";
        }
    }
}
