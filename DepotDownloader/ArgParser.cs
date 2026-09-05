// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace DepotDownloader
{
    /// <summary>
    /// Shared command-line argument parsing for all sub-commands. Wraps a raw
    /// <c>string[] args</c> array, tracks which tokens were consumed, and exposes
    /// typed lookups that understand multiple aliases for the same flag
    /// (e.g. "-username"/"-user", "-verbose"/"-v").
    /// </summary>
    class ArgParser
    {
        private readonly string[] args;
        private readonly bool[] consumed;

        public ArgParser(string[] args)
        {
            this.args = args;
            consumed = new bool[args.Length];
        }

        private int IndexOfAny(string[] names)
        {
            for (var x = 0; x < args.Length; x++)
            {
                foreach (var name in names)
                {
                    if (args[x].Equals(name, StringComparison.OrdinalIgnoreCase))
                    {
                        consumed[x] = true;
                        return x;
                    }
                }
            }

            return -1;
        }

        /// <summary>True if any of the given flag names is present.</summary>
        public bool HasFlag(params string[] names) => IndexOfAny(names) > -1;

        /// <summary>Typed value following the first matching name, or <paramref name="defaultValue"/> if absent or unparsable.</summary>
        public T Get<T>(T defaultValue, params string[] names)
        {
            var index = IndexOfAny(names);
            if (index == -1 || index == args.Length - 1)
                return defaultValue;

            var converter = TypeDescriptor.GetConverter(typeof(T));
            if (converter == null)
                return defaultValue;

            try
            {
                var value = (T)converter.ConvertFromString(args[index + 1]);
                consumed[index + 1] = true;
                return value;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentException or NotSupportedException)
            {
                return defaultValue;
            }
        }

        /// <summary>Typed value following the first matching name, or null if the flag is absent.</summary>
        public T? GetNullable<T>(params string[] names) where T : struct =>
            HasFlag(names) ? Get<T>(default, names) : null;

        /// <summary>All consecutive typed values following the first matching name, until the next flag-looking token.</summary>
        public List<T> GetList<T>(params string[] names)
        {
            var list = new List<T>();
            var index = IndexOfAny(names);
            if (index == -1)
                return list;

            var converter = TypeDescriptor.GetConverter(typeof(T));

            for (var i = index + 1; i < args.Length; i++)
            {
                if (args[i].Length > 0 && args[i][0] == '-')
                    break;

                if (converter == null)
                    continue;

                try
                {
                    list.Add((T)converter.ConvertFromString(args[i]));
                    consumed[i] = true;
                }
                catch (Exception ex) when (ex is FormatException or ArgumentException or NotSupportedException)
                {
                    // Not a value belonging to this list - leave unconsumed so it still gets
                    // flagged by WarnUnconsumed() if nothing else claims it.
                }
            }

            return list;
        }

        /// <summary>
        /// The Nth (0-based) remaining token that doesn't look like a flag and hasn't
        /// already been consumed - used for positional arguments like file/folder paths.
        /// </summary>
        public string Positional(int index)
        {
            var seen = 0;
            for (var x = 0; x < args.Length; x++)
            {
                if (consumed[x] || (args[x].Length > 0 && args[x][0] == '-'))
                    continue;

                if (seen == index)
                {
                    consumed[x] = true;
                    return args[x];
                }

                seen++;
            }

            return null;
        }

        /// <summary>Warns about any tokens that were never consumed by a HasFlag/Get/GetList/Positional call.</summary>
        public void WarnUnconsumed()
        {
            var printError = false;

            for (var index = 0; index < consumed.Length; index++)
            {
                if (!consumed[index])
                {
                    printError = true;
                    Console.Error.WriteLine($"Argument #{index + 1} {args[index]} was not used.");
                }
            }

            if (printError)
            {
                Console.Error.WriteLine("Make sure you specified the arguments correctly. Check --help for correct arguments.");
                Console.Error.WriteLine();
            }
        }
    }
}
