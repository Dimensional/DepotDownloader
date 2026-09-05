// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    public enum ReconstructFileStatus
    {
        Completed,
        Failed,
        SkippedSymlink,
        ValidationFailed
    }

    public class ReconstructFileResult
    {
        public string FileName { get; init; }
        public ReconstructFileStatus Status { get; init; }
        public string ErrorMessage { get; init; }
    }

    public class ReconstructSummary
    {
        public int TotalFiles { get; set; }
        public int CompletedFiles { get; set; }
        public int FailedFiles { get; set; }
        public int SkippedSymlinks { get; set; }
        public int ValidationFailures { get; set; }
        public List<ReconstructFileResult> Results { get; } = [];
    }

    public class ReconstructOptions
    {
        /// <summary>Max parallel file writers. 0 = CPU count - 1.</summary>
        public int MaxParallelism { get; set; }

        /// <summary>Verify each file's whole-content SHA1 against the manifest after writing.</summary>
        public bool Validate { get; set; }

        /// <summary>Stop enqueuing further files as soon as one fails; already-started files still finish.</summary>
        public bool FailFast { get; set; }

        /// <summary>Literal relative paths to include (forward-slash normalized, case-insensitive). Null/empty = include all.</summary>
        public HashSet<string> IncludeFiles { get; set; }

        /// <summary>"regex:"-prefixed patterns to include, same format as -filelist elsewhere in this codebase.</summary>
        public List<Regex> IncludeRegexes { get; set; }

        public bool Verbose { get; set; }
    }

    /// <summary>
    /// Rebuilds a depot's installed files from a manifest plus a chunk source (loose folder or
    /// chunkstore), entirely offline. Modeled on the live download pipeline's per-file/per-chunk
    /// assembly shape (ContentDownloader.StandardDownload.cs) with the network fetch replaced by
    /// a local chunk source, and deliberately simpler: every in-scope file is always rewritten
    /// from scratch (no reuse-from-existing-output-file logic - there's no previous-manifest
    /// diff or partial-download state to trust here), which makes reconstruct trivially safe to
    /// re-run after an interruption.
    /// </summary>
    public static class ReconstructEngine
    {
        public static async Task<ReconstructSummary> RunAsync(
            DepotManifest manifest,
            IChunkSource chunkSource,
            string outputDir,
            ReconstructOptions options = null)
        {
            options ??= new ReconstructOptions();
            var summary = new ReconstructSummary();

            var outputRoot = Path.GetFullPath(outputDir);
            Directory.CreateDirectory(outputRoot);

            var files = (manifest.Files ?? [])
                .Where(f => IsFileIncluded(f.FileName, options))
                .ToList();

            summary.TotalFiles = files.Count;

            var regularFiles = new List<DepotManifest.FileData>();

            // Phase A: directories and symlinks are cheap and sequential - no chunk work involved.
            foreach (var file in files)
            {
                if (!TryResolveOutputPath(outputRoot, file.FileName, out var outPath, out var pathError))
                {
                    summary.Results.Add(new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.Failed, ErrorMessage = pathError });
                    summary.FailedFiles++;
                    continue;
                }

                if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                {
                    Directory.CreateDirectory(outPath);
                    continue;
                }

                if (file.Flags.HasFlag(EDepotFileFlag.Symlink))
                {
                    HandleSymlink(file, outPath, summary, options);
                    continue;
                }

                regularFiles.Add(file);
            }

            if (regularFiles.Count == 0)
            {
                return summary;
            }

            // Canary check: decrypt/decompress/verify one chunk before committing to the full
            // parallel run. A wrong or missing depot key fails every chunk identically, so
            // reporting that per-file (potentially thousands of times) would just be noise -
            // fail the whole run immediately instead with one clear message. This can't fully
            // distinguish "wrong key" from "this one chunk happens to be corrupt", but picking
            // that apart isn't worth the complexity; the error message says both are possible.
            var canaryFile = regularFiles.FirstOrDefault(f => f.Chunks.Count > 0);
            if (canaryFile != null)
            {
                try
                {
                    chunkSource.GetChunk(canaryFile.Chunks[0]);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        $"Failed to read the first chunk needed for reconstruction ({canaryFile.FileName}): {ex.Message}. " +
                        "This usually means the depot key is wrong, or the archive is corrupt.", ex);
                }
            }

            options.MaxParallelism = Util.ResolveParallelism(options.MaxParallelism);

            var results = new ConcurrentBag<ReconstructFileResult>();
            var completed = 0;
            var failed = 0;
            var validationFailed = 0;

            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = options.MaxParallelism };

            await Parallel.ForEachAsync(regularFiles, parallelOptions, (file, ct) =>
            {
                var result = ProcessFile(file, chunkSource, outputRoot, options);
                results.Add(result);

                switch (result.Status)
                {
                    case ReconstructFileStatus.Completed:
                        System.Threading.Interlocked.Increment(ref completed);
                        break;
                    case ReconstructFileStatus.ValidationFailed:
                        System.Threading.Interlocked.Increment(ref validationFailed);
                        break;
                    default:
                        System.Threading.Interlocked.Increment(ref failed);
                        break;
                }

                if (options.Verbose || result.Status != ReconstructFileStatus.Completed)
                {
                    lock (Console.Out)
                    {
                        var marker = result.Status == ReconstructFileStatus.Completed ? "✓" : "✗";
                        Console.WriteLine(result.ErrorMessage != null
                            ? $"{marker} {result.FileName} - {result.ErrorMessage}"
                            : $"{marker} {result.FileName}");
                    }
                }

                if (result.Status != ReconstructFileStatus.Completed && options.FailFast)
                {
                    throw new InvalidOperationException($"Aborting: {result.FileName} failed ({result.ErrorMessage}) and -fail-fast was specified.");
                }

                return ValueTask.CompletedTask;
            });

            summary.Results.AddRange(results);
            summary.CompletedFiles += completed;
            summary.FailedFiles += failed;
            summary.ValidationFailures += validationFailed;

            return summary;
        }

        private static ReconstructFileResult ProcessFile(DepotManifest.FileData file, IChunkSource chunkSource, string outputRoot, ReconstructOptions options)
        {
            if (!TryResolveOutputPath(outputRoot, file.FileName, out var outPath, out var pathError))
            {
                return new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.Failed, ErrorMessage = pathError };
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outPath));

                using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.SetLength((long)file.TotalSize);

                    foreach (var chunk in file.Chunks)
                    {
                        byte[] data;
                        try
                        {
                            data = chunkSource.GetChunk(chunk);
                        }
                        catch (Exception ex)
                        {
                            var shaHex = Util.ToHex(chunk.ChunkID);
                            throw new IOException($"chunk {shaHex}: {ex.Message}", ex);
                        }

                        if ((uint)data.Length != chunk.UncompressedLength)
                        {
                            var shaHex = Util.ToHex(chunk.ChunkID);
                            throw new IOException($"chunk {shaHex} decompressed to {data.Length} bytes, expected {chunk.UncompressedLength}");
                        }

                        fs.Seek((long)chunk.Offset, SeekOrigin.Begin);
                        fs.Write(data, 0, data.Length);
                    }
                }

                if (file.Flags.HasFlag(EDepotFileFlag.Executable))
                {
                    PlatformUtilities.SetExecutable(outPath, true);
                }

                if (options.Validate)
                {
                    var (ok, error) = ValidateWholeFile(outPath, file);
                    if (!ok)
                    {
                        return new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.ValidationFailed, ErrorMessage = error };
                    }
                }

                return new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.Completed };
            }
            catch (Exception ex)
            {
                return new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.Failed, ErrorMessage = ex.Message };
            }
        }

        private static void HandleSymlink(DepotManifest.FileData file, string outPath, ReconstructSummary summary, ReconstructOptions options)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outPath));

                if (File.Exists(outPath) || Directory.Exists(outPath))
                {
                    File.Delete(outPath);
                }

                File.CreateSymbolicLink(outPath, file.LinkTarget);

                if (options.Verbose)
                {
                    Console.WriteLine($"✓ {file.FileName} -> {file.LinkTarget} (symlink)");
                }

                summary.Results.Add(new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.Completed });
                summary.CompletedFiles++;
            }
            catch (Exception ex)
            {
                // Symlink creation can fail for reasons outside our control (e.g. Windows without
                // Developer Mode/admin) - warn and move on rather than failing the whole run.
                Console.WriteLine($"Warning: failed to create symlink {file.FileName} -> {file.LinkTarget}: {ex.Message}");
                summary.Results.Add(new ReconstructFileResult { FileName = file.FileName, Status = ReconstructFileStatus.SkippedSymlink, ErrorMessage = ex.Message });
                summary.SkippedSymlinks++;
            }
        }

        private static (bool Ok, string Error) ValidateWholeFile(string path, DepotManifest.FileData file)
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return (false, "File missing after write");
            }

            if ((ulong)info.Length != file.TotalSize)
            {
                return (false, $"Length mismatch: expected {file.TotalSize}, got {info.Length}");
            }

            if (file.FileHash == null || file.FileHash.Length == 0)
            {
                return (true, null);
            }

            var actualHash = Util.FileSHAHash(path);
            if (!actualHash.AsSpan().SequenceEqual(file.FileHash))
            {
                return (false, $"SHA1 mismatch: expected {Util.ToHex(file.FileHash)}, got {Util.ToHex(actualHash)}");
            }

            return (true, null);
        }

        private static bool IsFileIncluded(string fileName, ReconstructOptions options)
        {
            var hasIncludeFiles = options.IncludeFiles is { Count: > 0 };
            var hasIncludeRegexes = options.IncludeRegexes is { Count: > 0 };
            if (!hasIncludeFiles && !hasIncludeRegexes)
            {
                return true;
            }

            var normalized = fileName.Replace('\\', '/');

            if (hasIncludeFiles && options.IncludeFiles.Contains(normalized))
            {
                return true;
            }

            if (hasIncludeRegexes)
            {
                foreach (var rgx in options.IncludeRegexes)
                {
                    if (rgx.IsMatch(normalized))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Resolves a manifest file entry's path against the output root, rejecting anything
        /// that would escape it (e.g. via ".." segments) - manifest content originates from an
        /// archive, not something to trust blindly when it's about to be used as a file path.
        /// </summary>
        private static bool TryResolveOutputPath(string outputRoot, string fileName, out string outPath, out string error)
        {
            outPath = null;
            error = null;

            var candidate = Path.GetFullPath(Path.Combine(outputRoot, fileName));

            if (!candidate.StartsWith(outputRoot, StringComparison.OrdinalIgnoreCase) ||
                (candidate.Length > outputRoot.Length && candidate[outputRoot.Length] != Path.DirectorySeparatorChar))
            {
                error = $"Refusing to write outside output directory: {fileName}";
                return false;
            }

            outPath = candidate;
            return true;
        }
    }
}
