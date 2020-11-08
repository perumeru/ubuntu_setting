using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace urlCheck
{
    class Program
    {
        [STAThread]
        static int Main(string[] argss)
        {
            Console.WriteLine("◆◆◆◆◆◆◆◆◆◆◆◆Blacklist最適化ツール◆◆◆◆◆◆◆◆◆◆◆◆◆");
            Console.WriteLine("◆「0」blacklist.txtを指定した.番目で昇順ソートします。              ◆");
            Console.WriteLine("◆「1」whitelist.txtのurlをblacklist.txtから省き、昇順ソートします。 ◆");
            Console.WriteLine("◆「2」dnsで解決不可のurlを省きます。                                ◆");
            Console.WriteLine("◆「3」何もしません。                                                ◆");
            Console.WriteLine("◆ ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆");
            string cstr = Console.ReadLine();
            if (cstr == "0")
            {
                Console.WriteLine("何個目の.で並び替える?その番目に.がない場合ははじきます:");
                int cnt = int.Parse(Console.ReadLine());
                string[] stringbuf = File.ReadAllLines(@"blacklist.txt");
                List<string[]> vs = new List<string[]>();
                try
                {
                    using (StreamWriter sw = new StreamWriter(@"rs\blacklist.txt"))
                    {
                        sw.Write("■■■■■■■■■■ここから省かれたurl■■■■■■■■■■");
                        foreach (string args in stringbuf)
                        {
                            string[] buff = args.Split('.');
                            if (buff.Length > cnt)
                            {
                                vs.Add(buff);
                            }
                            else
                            {
                                sw.Write('\n' + args);

                            }
                        }
                        var sorted = vs.OrderBy(e => e[cnt]).ToArray();

                        sw.Write('\n' + "■■■■■■■■■■ここから対象のurl■■■■■■■■■■");
                        StringBuilder stringBuilder = new StringBuilder();
                        foreach (string[] args in sorted)
                        {
                            foreach (var e in args)
                            {
                                stringBuilder.Append(e + '.');
                            }
                            string wrt = stringBuilder.Remove(stringBuilder.Length - 1, 1).ToString();
                            sw.Write('\n' + wrt);


                            stringBuilder.Clear();
                        }
                    }
                }
                catch (System.Exception fe) { Console.WriteLine(fe.Message); }
            }
            else if (cstr == "1")
            {
                try
                {
                    string[] readText = File.ReadAllLines(@"whitelist.txt");
                    string[] buffer = File.ReadAllLines(@"blacklist.txt");

                    for (int i = 0; i < buffer.Length; i++)
                    {
                        string args2 = buffer[i];
                        foreach (string args in readText)
                        {
                            if (args == args2) buffer[i] = "";
                        }
                    }
                    buffer = buffer.Distinct().OrderBy(x => x).ToArray();
                    readText = null;
                    using (StreamWriter sw = new StreamWriter(@"rs\blacklist.txt"))
                    {
                        bool one = false;
                        foreach (string args in buffer)
                        {
                            if (args.Contains("."))
                            {
                                if (one) sw.Write('\n' + args); else { sw.Write(args); one = true; }
                            }
                        }
                    }
                }
                catch (System.Exception fe) { Console.WriteLine(fe.Message); }
            }
            else if (cstr == "2")
            {
                Console.WriteLine("update1-");
                StreamReader sr;
                StreamWriter sw;
                char[] alpha = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ-".ToCharArray();
                using (sr = new StreamReader(@"blacklist.txt"))
                {
                    using (sw = new StreamWriter(@"rs\ans.txt"))
                    {
                        IPHostEntry ipEntry;
                        IPAddress[] ipAddr;
                        int count = 0;
                        while (sr.Peek() != -1)
                        {
                            string args = sr.ReadLine().ToString();
                            try
                            {
                                if (args.IndexOfAny(alpha) != -1)
                                {
                                    ipEntry = Dns.GetHostEntry(args);
                                    ipAddr = ipEntry.AddressList;
                                    sw.WriteLine(args);
                                    Console.Write("\r{0}", count);
                                    count++;
                                }
                                else
                                {
                                    ipEntry = Dns.GetHostEntry(args);
                                    sw.WriteLine(ipEntry.HostName);
                                    Console.Write("\r{0}", count);
                                    count++;
                                }
                            }
                            catch (System.Net.Sockets.SocketException) { Console.WriteLine("Error: " + args); }
                            catch (System.FormatException) { Console.WriteLine("Error: " + args); }
                            catch (Exception ex) { Trace.WriteLine(ex.Message); }
                        }
                    }
                }
                try
                {
                    var p = new Process();
                    p.StartInfo.FileName = "shutdown.exe";
                    p.StartInfo.Arguments = "-s -t 60";
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();
                    Console.WriteLine("yes");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }
            return 0;
        }
    }
}
