namespace SteamOpenIdConnectProvider.Domains.Common;

public sealed class HostingConfig
{
    public const string Config = "Hosting";

    public string? BasePath { get; set; }

    public string? PublicOrigin { get; set; }

    /// <summary>Where the signing key is persisted (mount a volume). Empty = library default next to the binary.</summary>
    public string? SigningKeyPath { get; set; }
}
