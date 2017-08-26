using System;
using DankMemes.GPSOAuthSharp;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace GPSOAuthDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            MainAsync().Wait();
        }

        static async Task MainAsync()
        {
            Console.WriteLine("Google account email: ");
            string email = Console.ReadLine();
            Console.WriteLine("Password: ");
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring(0, password.Length - 1);
                        int pos = Console.CursorLeft;
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }
            Console.WriteLine();
            GPSOAuthClient client = new GPSOAuthClient(email, password);
            IDictionary<string, string> response = await client.PerformMasterLoginAsync();
            string json = JsonConvert.SerializeObject(response, Formatting.Indented);
            Console.WriteLine(json);
            if (response.ContainsKey("Token"))
            {
                string token = response["Token"];
                IDictionary<string, string> oauthResponse = await client
                    .PerformOAuthAsync(token, "sj", "com.google.android.music",
                    "38918a453d07199354f8b19af05ec6562ced5788");
                string oauthJson = JsonConvert.SerializeObject(oauthResponse, Formatting.Indented);
                Console.WriteLine(oauthJson);
            }
            else
            {
                Console.WriteLine("MasterLogin failed (check credentials)");
            }
            Console.ReadLine();
        }
    }
}
