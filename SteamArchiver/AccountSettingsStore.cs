// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using ProtoBuf;

namespace SteamArchiver
{
    [ProtoContract]
    class AccountSettingsStore
    {
        // Member 1 was a Dictionary<string, byte[]> for SentryData.

        [ProtoMember(2, IsRequired = false)]
        public ConcurrentDictionary<string, int> ContentServerPenalty { get; private set; }

        // Member 3 was a Dictionary<string, string> for LoginKeys.

        [ProtoMember(4, IsRequired = false)]
        public Dictionary<string, string> LoginTokens { get; private set; }

        [ProtoMember(5, IsRequired = false)]
        public Dictionary<string, string> GuardData { get; private set; }

        string FileName;

        AccountSettingsStore()
        {
            ContentServerPenalty = new ConcurrentDictionary<string, int>();
            LoginTokens = [];
            GuardData = [];
        }

        static bool Loaded
        {
            get { return Instance != null; }
        }

        public static AccountSettingsStore Instance;

        public static void LoadFromFile(string filename)
        {
            if (Loaded)
                throw new Exception("Config already loaded");

            string exeDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string filePath = Path.Combine(exeDirectory, filename);

            if (File.Exists(filePath))
            {
                try
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                    using var ds = new DeflateStream(fs, CompressionMode.Decompress);
                    Instance = Serializer.Deserialize<AccountSettingsStore>(ds);
                    Console.WriteLine($"Loaded account settings from {filePath}");
                }
                catch (IOException ex)
                {
                    Console.WriteLine("Failed to load account settings: {0}", ex.Message);
                    Instance = new AccountSettingsStore();
                }
            }
            else
            {
                Instance = new AccountSettingsStore();
            }

            Instance.FileName = filePath;
        }

        public static void Save()
        {
            if (!Loaded)
                throw new Exception("Saved config before loading");

            try
            {
                using var fs = new FileStream(Instance.FileName, FileMode.Create, FileAccess.Write);
                using var ds = new DeflateStream(fs, CompressionMode.Compress);
                Serializer.Serialize(ds, Instance);
                Console.WriteLine($"Saved account settings to {Instance.FileName}");
            }
            catch (IOException ex)
            {
                Console.WriteLine("Failed to save account settings: {0}", ex.Message);
            }
        }
    }
}