using System;
using DankMemes.GPSOAuthSharp;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace GPSOAuthDemo
{
    class Program
    {
        static void Main(string[] args)
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
            Dictionary<string, string> response = client.PerformMasterLogin();
            string json = JsonConvert.SerializeObject(response, Formatting.Indented);
            Console.WriteLine(json);
            if (response.ContainsKey("Token"))
            {
                string token = response["Token"];
                Dictionary<string, string> oauthResponse = client
                    .PerformOAuth(token, "sj", "com.google.android.music",
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
