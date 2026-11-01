using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class RecoverySecurityTests
{
  [WindowsFact]
  public void PhysicalDirectoryIdentitySurvivesRenameAndRejectsFilesOrMissingPaths()
  {
    using var f = new Fixture();
    var original = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(f.Root, "identity-original"));
    var other = BrokerPlatform.Current.Files.CreatePrivateDirectory(Path.Combine(f.Root, "identity-other"));
    var identity = BrokerPlatform.Current.Files.DirectoryIdentity(original);
    Assert.NotEqual(identity, BrokerPlatform.Current.Files.DirectoryIdentity(other));
    var renamed = Path.Combine(f.Root, "identity-renamed");
    Directory.Move(original, renamed);
    Assert.Equal(identity, BrokerPlatform.Current.Files.DirectoryIdentity(renamed));
    Assert.Equal("directory-identity-unavailable", Assert.Throws<BrokerException>(() => BrokerPlatform.Current.Files.DirectoryIdentity(original)).Code);
    Assert.False(Directory.Exists(original));
    var file = Path.Combine(f.Root, "ordinary-file");
    File.WriteAllText(file, "no secrets");
    Assert.Equal("directory-identity-unavailable", Assert.Throws<BrokerException>(() => BrokerPlatform.Current.Files.DirectoryIdentity(file)).Code);
  }

  [WindowsFact]
  public void MissingPublishedDatabaseNeverCreatesAnEmptyReplacement()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    var path = Path.Combine(f.Vault.VersionPath(f.Published.StorageVersion), "credentials.db");
    File.Delete(path);
    Assert.ThrowsAny<Exception>(() => new CredentialStore(f.Vault, f.Vault.CurrentVersion(), f.Key));
    Assert.False(File.Exists(path));
  }
  [WindowsFact]
  public void RecordRevisionAndAttributionAreAuthenticated()
  {
    using var f = new Fixture();
    f.Store.Dispose();
    using (var db = new Database(Path.Combine(f.Vault.VersionPath(f.Published.StorageVersion), "credentials.db"), false))
      db.Execute("UPDATE records SET updated='forged-client' WHERE id='credential-1'");
    f.Restart();
    Assert.ThrowsAny<CryptographicException>(() => f.Store.Get(Fixture.A, "credential-1"));
  }
  [WindowsFact]
  public void BroadFilePermissionsAreRejectedWithoutSilentlyRewritingExistingAcl()
  {
    // This integration test deliberately changes a real Windows DACL.
    if (!OperatingSystem.IsWindows()) return;
    using var f = new Fixture();
    var path = Path.Combine(f.Vault.Root, "unsafe.txt");
    File.WriteAllText(path, "no secrets", Encoding.UTF8);
    var info = new FileInfo(path);
    var original = info.GetAccessControl();
    var acl = info.GetAccessControl();
    acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow));
    info.SetAccessControl(acl);
    try { Assert.Equal("file-permissions-too-broad", Assert.Throws<BrokerException>(() => BrokerPlatform.Current.Files.ValidateTree(f.Vault.Root)).Code); }
    finally { info.SetAccessControl(original); }
  }
  [WindowsFact]
  public void RestrictedOwnershipCannotBeForgedThroughExtraCreateFields()
  {
    var json = "{\"credentialId\":\"id\",\"operationId\":\"op\",\"contentType\":\"custom\",\"payloadFormatVersion\":1,\"payload\":\"\",\"metadata\":{},\"createdByClientId\":\"forged\"}";
    Assert.Throws<System.Text.Json.JsonException>(() => Protocol.Decode<CreateCredential>(Protocol.Parse(Encoding.UTF8.GetBytes(json))));
  }
}
