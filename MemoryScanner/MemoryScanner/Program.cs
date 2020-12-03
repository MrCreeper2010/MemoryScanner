using ProcessHacker.Native.Api;
using ProcessHacker.Native.Objects;
using ProcessHacker.Native.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;


namespace MemoryScanner
{
    class Program
    {
        /// <summary>
        /// 
        /// Simple Memory-Scan without any third party software like strings2 or processdump
        /// Special thanks to Silent Screenshare tool and ProcessHacker
        /// 
        /// Original Credits: 
        /// - ProcessHacker 2 (https://processhacker.sourceforge.io/downloads.php)
        /// - Silent Screenshare tool (https://github.com/Silenttttttt/Silent-scanner)
        /// 
        /// </summary>

        public static ProcessAccess MinProcessReadMemoryRights = ProcessAccess.VmRead;

        public static bool IsChar(byte b)
        {
            return (b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9;
        }

        static void Main()
        {
            #region Process-Priority

            Process.GetCurrentProcess().PriorityClass = System.Diagnostics.ProcessPriorityClass.RealTime;

            new Thread(() =>
            {
                while (true)
                {
                    foreach (ProcessThread processThread in Process.GetCurrentProcess().Threads)
                        if (processThread.ThreadState != System.Diagnostics.ThreadState.Terminated)
                            processThread.PriorityLevel = ThreadPriorityLevel.TimeCritical;
                    Thread.Sleep(1);
                }
            }).Start();

            #endregion

            #region Variables

            ProcessHandle phandle = new ProcessHandle(Process.GetProcessesByName("explorer")[0].Id,
                       ProcessAccess.QueryInformation |
                       MinProcessReadMemoryRights);

            int allactions, count, totalstrings;
            allactions = count = totalstrings = 0;

            int minsize = 4;

            List<string> memory_string = new List<string>();

            bool unicode, opt_priv, opt_map, isUnicode, opt_img;
            opt_img = isUnicode = false;
            unicode = opt_priv = opt_map = true;

            byte byte2, byte1;
            byte2 = byte1 = 0;

            byte[] clean_string = Encoding.Unicode.GetBytes("\0");

            #endregion

            #region Scan Memory

            phandle.EnumMemory((info) =>
            {
                if (info.Protect == MemoryProtection.AccessDenied) return true;
                if (info.State != MemoryState.Commit) return true;

                if ((!opt_priv) && (info.Type == MemoryType.Private)) return true;
                if ((!opt_img) && (info.Type == MemoryType.Image)) return true;
                if ((!opt_map) && (info.Type == MemoryType.Mapped)) return true;

                byte[] data = new byte[info.RegionSize.ToInt32()];
                int bytesRead = 0;
                totalstrings += info.RegionSize.ToInt32();

                try
                {
                    bytesRead = phandle.ReadMemory(info.BaseAddress, data, data.Length);

                    if (bytesRead == 0)
                        return true;
                }
                catch { return true; }

                StringBuilder curstr = new StringBuilder();

                for (int i = 0; i < bytesRead; i++)
                {
                    bool isChar = IsChar(data[i]);

                    if (unicode && isChar && isUnicode && byte1 > 0)
                    {
                        isUnicode = false;

                        if (curstr.Length > 0)
                            curstr.Remove(curstr.Length - 1, 1);

                        curstr.Append((char)data[i]);
                    }
                    else if (isChar)
                        curstr.Append((char)data[i]);

                    else if (unicode && data[i] == 0 && IsChar(byte1) && !IsChar(byte2))
                        isUnicode = true; // skip null byte

                    else if (unicode &&
                        data[i] == 0 && IsChar(byte1) && IsChar(byte2) && curstr.Length < minsize)
                    {
                        // ... [char] [char] *[null]* ([char] [null] [char] [null]) ...
                        //                   ^ we are here
                        isUnicode = true;
                        curstr = new StringBuilder();
                        curstr.Append((char)byte1);
                    }
                    else
                    {
                        if (curstr.Length >= minsize && curstr.Length <= 1000)
                        {
                            int length = curstr.Length;

                            if (isUnicode)
                                length *= 2;

                            allactions++;
                            memory_string.Add(curstr.ToString());
                            count++;
                        }

                        isUnicode = false;
                        curstr = new StringBuilder();
                    }

                    byte2 = byte1;
                    byte1 = data[i];
                }
                data = null;

                return true;
            });
            phandle.Dispose();

            #endregion

            /*
             * Get if Memory's strings contains our string
             */

            for (int i = 0; i < memory_string.Count; i++)
            {
                if (memory_string[i].ToUpper().Contains("JNATIVEHOOK"))
                    Console.WriteLine(memory_string[i]);
            }

            Console.WriteLine("Done!");
            Console.ReadLine();
        }
    }
}
