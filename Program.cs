using System;
using System.IO;
using System.Windows.Forms;

namespace IcarusRDP_builder
{
    internal class Program
    {
        public static string buildserverpath = Application.StartupPath + "\\BuildServer";

        public static string xamppath = Application.StartupPath + "\\BuildServer\\ICARUS\\";

        public static dynamic responseofgg;

        public static bool bypass = true;

        public static string CanIBuild(string username)
        {
            try
            {
                if (bypass)
                {
                    return "true";
                }
                return "failed";
            }
            catch (Exception ex)
            {
                File.WriteAllText("exceptionusercheck.txt", ex.ToString());
                return "error";
            }
        }

        private static void Main(string[] args)
        {
            try
            {
                BuildFile.Build(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Invalid Arguments");
                File.WriteAllText("exceptionmain.txt", ex.ToString());
            }
        }
    }
}
