using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace RichOnline.Admin;

internal static class JsonFormatting
{
    public static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        TypeInfoResolver = new DefaultJsonTypeInfoResolver()
    };
}
