// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using SteamKit2;

namespace DepotDownloader
{
    /// <summary>
    /// Thrown when a manifest-referenced chunk can't be found in the chunk source (loose folder
    /// or chunkstore) reconstruct is reading from - the same exception regardless of source kind,
    /// so callers don't need to care which one raised it.
    /// </summary>
    public class ChunkNotFoundException : Exception
    {
        public string ChunkSha { get; }

        public ChunkNotFoundException(string chunkSha, string context = null)
            : base($"Chunk {chunkSha} not found" + (context != null ? $" ({context})" : ""))
        {
            ChunkSha = chunkSha;
        }
    }

    /// <summary>
    /// Abstracts over where reconstruct reads decrypted, decompressed, SHA1-verified chunk bytes
    /// from - a loose chunk folder or a packed chunkstore - so the assembly engine doesn't need
    /// to know which. Implementations always return fully processed bytes ready to write to disk.
    /// </summary>
    public interface IChunkSource : IDisposable
    {
        byte[] GetChunk(DepotManifest.ChunkData chunk);
    }

    /// <summary>
    /// Reads chunks from a loose folder in the raw-archive layout (depot/&lt;id&gt;/chunk/&lt;sha&gt;).
    /// Raw-archive loose chunks are always still encrypted+compressed - `download -raw` never
    /// stores a decrypted variant loosely (the "_decrypted" naming convention only applies to
    /// chunks unpacked from an already-decrypted chunkstore, not to freshly archived chunks).
    /// </summary>
    public sealed class LooseChunkSource(string folder, byte[] depotKey) : IChunkSource
    {
        public byte[] GetChunk(DepotManifest.ChunkData chunk)
        {
            var shaHex = Util.ToHex(chunk.ChunkID);
            var path = Path.Combine(folder, shaHex);

            if (!File.Exists(path))
            {
                throw new ChunkNotFoundException(shaHex, $"not found in {folder}");
            }

            byte[] raw;
            try
            {
                raw = File.ReadAllBytes(path);
            }
            catch (Exception ex)
            {
                throw new ChunkNotFoundException(shaHex, $"failed to read from {folder}: {ex.Message}");
            }

            return Chunkstore.ProcessChunkStatic(shaHex, raw, isEncrypted: true, depotKey);
        }

        public void Dispose()
        {
            // No unmanaged resources - nothing to do.
        }
    }

    /// <summary>
    /// Reads chunks from a packed chunkstore, reusing its own encryption mode and depot key.
    /// </summary>
    public sealed class ChunkstoreChunkSource(Chunkstore chunkstore, bool ownsChunkstore = false) : IChunkSource
    {
        public byte[] GetChunk(DepotManifest.ChunkData chunk)
        {
            try
            {
                return chunkstore.GetChunk(chunk.ChunkID, process: true);
            }
            catch (KeyNotFoundException)
            {
                var shaHex = Util.ToHex(chunk.ChunkID);
                throw new ChunkNotFoundException(shaHex, "not found in chunkstore");
            }
        }

        public void Dispose()
        {
            if (ownsChunkstore)
            {
                chunkstore.Dispose();
            }
        }
    }
}
