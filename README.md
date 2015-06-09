# GPSOAuthSharp
A .NET client library for Google Play Services OAuth written in C#.

This is a C# port of https://github.com/simon-weber/gpsoauth

## NuGet package
You can find this on NuGet at https://www.nuget.org/packages/GPSOAuthSharp/

## Usage
Construct a `DankMemes.GPSOAuthSharp.GPSOAuthClient(email, password)`.

Use `PerformMasterLogin()` or `PerformOAuth()` to retrieve a `Dictionary<string, string>` of response values. 

Sample response values (sample program coming soon): 

![](http://i.imgur.com/GLRCWs9.png)

## Goals
This project intends to follow the Google-specific parts of the Python implementation extremely carefully, so that any changes made to the Python implementation can be easily applied to this.