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
  public void ExistingFilePermissionsAreAcceptedWithoutRewritingAcl()
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
    try
    {
      var expected = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
      BrokerPlatform.Current.Files.ValidateTree(f.Vault.Root);
      Assert.Equal(expected, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }
    finally { info.SetAccessControl(original); }
  }
  [WindowsFact]
  public void UserSelectedDirectoryKeepsAclAndCopiedBackupReopensWithOriginalKeys()
  {
    if (!OperatingSystem.IsWindows()) return;
    var root = Path.Combine(Path.GetTempPath(), "AstraBackup-" + Crypto.RandomId());
    var data = Directory.CreateDirectory(Path.Combine(root, "selected")).FullName;
    var keys = Path.Combine(root, "keys");
    var info = new DirectoryInfo(data);
    var acl = info.GetAccessControl();
    acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
    info.SetAccessControl(acl);
    var before = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
    try
    {
      string vaultId;
      using (var vault = Vault.Open(data, keys, true))
      {
        vaultId = vault.Manifest.VaultId;
        vault.Initialize(Fixture.A, new("export", "watermark", [new("record", "opaque", 1, Fixture.Payload("SECRET"), [])]));
        foreach (var file in new[] { "manifest.json", "control.db", "control.db-wal", "control.db-shm" })
        {
          var rules = new FileInfo(Path.Combine(data, file)).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
          foreach (FileSystemAccessRule rule in rules)
            Assert.True(rule.AccessControlType != AccessControlType.Allow ||
              rule.IdentityReference.Equals(WindowsIdentity.GetCurrent().User) ||
              rule.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
        }
      }
      Assert.Equal(before, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
      // A normal manual backup does not preserve the physical directory ID or private ACLs.
      var copy = Directory.CreateDirectory(Path.Combine(root, "restored")).FullName;
      foreach (var directory in Directory.EnumerateDirectories(data, "*", SearchOption.AllDirectories))
        Directory.CreateDirectory(Path.Combine(copy, Path.GetRelativePath(data, directory)));
      foreach (var file in Directory.EnumerateFiles(data, "*", SearchOption.AllDirectories))
        File.Copy(file, Path.Combine(copy, Path.GetRelativePath(data, file)));
      using var restored = Vault.Open(copy, keys);
      Assert.Equal(vaultId, restored.Manifest.VaultId);
      var version = restored.CurrentVersion();
      using var store = new CredentialStore(restored, version, restored.LoadKey(version));
      Assert.Equal(Fixture.Payload("SECRET"), store.Get(Fixture.A, "record").Payload);
    }
    finally { Directory.Delete(root, true); }
  }
  [WindowsFact]
  public void UserSelectedDirectoryWithModifyAccessPublishesWithoutChangingOwnershipOrDirectoryAcl()
  {
    if (!OperatingSystem.IsWindows()) return;
    var root = Path.Combine(Path.GetTempPath(), "AstraModifyAccess-" + Crypto.RandomId());
    var parent = Directory.CreateDirectory(root);
    var user = WindowsIdentity.GetCurrent().User!;
    var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
    var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
    var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
    var acl = new DirectorySecurity();
    acl.SetAccessRuleProtection(true, false);
    acl.AddAccessRule(new FileSystemAccessRule(authenticatedUsers, FileSystemRights.Modify,
      inheritance, PropagationFlags.None, AccessControlType.Allow));
    foreach (var principal in new[] { administrators, system })
      acl.AddAccessRule(new FileSystemAccessRule(principal, FileSystemRights.FullControl,
        inheritance, PropagationFlags.None, AccessControlType.Allow));
    // Use the same .NET ACL API as the broker. PowerShell Set-Acl can enable ownership
    // privileges and hide the failure encountered by an ordinary application process.
    parent.SetAccessControl(acl);
    try
    {
      var selected = Directory.CreateDirectory(Path.Combine(root, "selected"));
      var parentBefore = parent.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
      var selectedBefore = selected.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
      var ordinary = Path.Combine(selected.FullName, "ordinary.txt");
      File.WriteAllText(ordinary, "no secrets");
      var inherited = new FileInfo(ordinary).GetAccessControl();
      var owner = inherited.GetOwner(typeof(SecurityIdentifier));
      var inheritedRules = inherited.GetAccessRules(true, true, typeof(SecurityIdentifier));
      foreach (FileSystemAccessRule rule in inheritedRules)
        Assert.False(rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Equals(user) &&
          (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl);
      File.Delete(ordinary);
      using (var vault = Vault.Open(selected.FullName, Path.Combine(root, "keys"), true))
      {
        vault.Initialize(Fixture.A, new("export", "watermark", [new("record", "opaque", 1, Fixture.Payload("FICTIONAL"), [])]));
        // Both atomic manifest creation and Database's initial file/WAL/SHM protection
        // must work without WRITE_OWNER inherited from the selected directory.
        foreach (var name in new[] { "manifest.json", "control.db", "control.db-wal", "control.db-shm" })
        {
          var fileAcl = new FileInfo(Path.Combine(selected.FullName, name)).GetAccessControl();
          Assert.Equal(owner, fileAcl.GetOwner(typeof(SecurityIdentifier)));
          Assert.True(fileAcl.AreAccessRulesProtected);
          var rules = fileAcl.GetAccessRules(true, true, typeof(SecurityIdentifier));
          Assert.Equal(2, rules.Count);
          foreach (FileSystemAccessRule rule in rules)
          {
            Assert.False(rule.IsInherited);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.True(rule.IdentityReference.Equals(user) || rule.IdentityReference.Equals(system));
            Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
          }
        }
      }
      Assert.Equal(parentBefore, parent.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
      Assert.Equal(selectedBefore, selected.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }
    finally { Directory.Delete(root, true); }
  }
  [WindowsFact]
  public void RestrictedOwnershipCannotBeForgedThroughExtraCreateFields()
  {
    var json = "{\"credentialId\":\"id\",\"operationId\":\"op\",\"contentType\":\"custom\",\"payloadFormatVersion\":1,\"payload\":\"\",\"metadata\":{},\"createdByClientId\":\"forged\"}";
    Assert.Throws<System.Text.Json.JsonException>(() => Protocol.Decode<CreateCredential>(Protocol.Parse(Encoding.UTF8.GetBytes(json))));
  }
}
