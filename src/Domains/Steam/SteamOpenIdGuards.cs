using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SteamOpenIdConnectProvider.Domains.Steam;

/// <summary>
/// Hardening for the Steam OpenID 2.0 leg (phattbeats fork):
///  - strict claimed_id check: exactly https://steamcommunity.com/openid/id/ + a 17-digit SteamID64
///  - openid.response_nonce one-shot replay guard on the Steam callback
/// </summary>
public static partial class SteamOpenIdGuards
{
    public static readonly Regex ClaimedIdRegex = new(
        @"^https://steamcommunity\.com/openid/id/(7656119\d{10})$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static bool TryGetSteamId(string? claimedId, [NotNullWhen(true)] out string? steamId)
    {
        steamId = null;
        if (string.IsNullOrEmpty(claimedId))
        {
            return false;
        }

        var match = ClaimedIdRegex.Match(claimedId);
        if (!match.Success)
        {
            return false;
        }

        steamId = match.Groups[1].Value;
        return true;
    }
}

/// <summary>
/// Rejects a Steam OpenID callback whose openid.response_nonce was already seen, is missing,
/// or carries a timestamp outside the login window. Runs before the authentication handler.
/// </summary>
public sealed class ResponseNonceReplayGuard(
    RequestDelegate next,
    IMemoryCache cache,
    IOptions<SteamConfig> config,
    ILogger<ResponseNonceReplayGuard> logger)
{
    public const string CallbackPath = "/signin-steam";
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.Equals(CallbackPath, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        string? mode;
        string? nonce;
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            mode = form["openid.mode"];
            nonce = form["openid.response_nonce"];
        }
        else
        {
            mode = context.Request.Query["openid.mode"];
            nonce = context.Request.Query["openid.response_nonce"];
        }

        if (!string.Equals(mode, "id_res", StringComparison.Ordinal))
        {
            // cancel / error / setup_needed carry no assertion; let the handler produce its own failure
            await next(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(nonce) || nonce.Length < 20 || nonce.Length > 255)
        {
            logger.LogWarning("Steam callback rejected: missing or malformed openid.response_nonce");
            await Reject(context, "missing response_nonce");
            return;
        }

        // OpenID 2.0 §10.1: nonce = UTC timestamp "yyyy-MM-ddTHH:mm:ssZ" followed by unique chars
        if (!DateTimeOffset.TryParseExact(nonce[..20], "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var issuedAt))
        {
            logger.LogWarning("Steam callback rejected: response_nonce has no valid timestamp");
            await Reject(context, "invalid response_nonce");
            return;
        }

        var window = TimeSpan.FromMinutes(config.Value.LoginTimeoutMinutes) + ClockSkew;
        var age = DateTimeOffset.UtcNow - issuedAt;
        if (age > window || age < -ClockSkew)
        {
            logger.LogWarning("Steam callback rejected: response_nonce timestamp outside the login window ({Age})", age);
            await Reject(context, "stale response_nonce");
            return;
        }

        var key = "steam-nonce:" + nonce;
        if (cache.TryGetValue(key, out _))
        {
            logger.LogWarning("Steam callback rejected: replayed openid.response_nonce");
            await Reject(context, "replayed response_nonce");
            return;
        }

        // Mark as used before the handler runs; a second delivery of the same assertion is refused
        // even if the first one is still in flight. Kept for twice the window so a late replay also fails.
        cache.Set(key, true, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = window + window,
            Size = 1,
        });

        await next(context);
    }

    private static Task Reject(HttpContext context, string reason)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "text/plain";
        return context.Response.WriteAsync($"The Steam login response was rejected: {reason}.");
    }
}
