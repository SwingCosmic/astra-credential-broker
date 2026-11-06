namespace Astra.Credentials;

// Portable file mechanics. Owner/ACL policy and physical directory identity belong to
// IPrivateFileSystem; these helpers do not pretend that permissions have been secured.
public static class LocalFiles
{
  public static string FullPath(string path)
  {
    Protocol.Require(!string.IsNullOrWhiteSpace(path), "invalid-path");
    var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    Protocol.Require(!full.StartsWith("\\\\", StringComparison.Ordinal) && Path.IsPathFullyQualified(full), "local-path-required");
    CheckLinks(full);
    return full;
  }

  public static void CheckLinks(string path)
  {
    for (var item = new DirectoryInfo(path); item is not null; item = item.Parent)
      if (item.Exists) Protocol.Require((item.Attributes & FileAttributes.ReparsePoint) == 0, "reparse-point-rejected");
    if (File.Exists(path)) Protocol.Require((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "reparse-point-rejected");
  }

  public static void WriteAtomic(string path, byte[] value, IPrivateFileSystem? files = null)
  {
    CheckLinks(path);
    var temp = Path.Combine(Path.GetDirectoryName(path)!, "." + Crypto.RandomId() + ".tmp");
    try
    {
      using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
      {
        files?.RestrictCreatedFile(temp);
        file.Write(value);
        file.Flush(true);
      }
      File.Move(temp, path, true);
    }
    finally { if (File.Exists(temp)) File.Delete(temp); }
  }

  public static FileStream AcquireLock(string path)
  {
    CheckLinks(path);
    try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
    catch (IOException) { throw new BrokerException("lock-busy"); }
  }

  public static bool ContainsPath(string parent, string child, StringComparison comparison) => child.Equals(parent, comparison) ||
    child.StartsWith(Path.EndsInDirectorySeparator(parent) ? parent : parent + Path.DirectorySeparatorChar, comparison);
}
