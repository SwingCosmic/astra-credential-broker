using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Astra.Credentials;

[SupportedOSPlatform("windows")]
internal sealed class WindowsPrivateFileSystem : IPrivateFileSystem
{
  private static SecurityIdentifier User => WindowsUserIdentity.CurrentSid;
  private static SecurityIdentifier SystemUser => new(WellKnownSidType.LocalSystemSid, null);
  public string CreatePrivateDirectory(string path)
  {
    var full = LocalFiles.FullPath(path);
    if (!Directory.Exists(full))
    {
      var acl = new DirectorySecurity();
      acl.SetOwner(User);
      acl.SetAccessRuleProtection(true, false);
      acl.AddAccessRule(new FileSystemAccessRule(User, FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
      // Retain OS maintenance access without granting other interactive users access.
      acl.AddAccessRule(new FileSystemAccessRule(SystemUser, FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
      new DirectoryInfo(full).Create(acl);
    }
    ValidatePrivateDirectory(full);
    return full;
  }

  public void ValidatePrivateDirectory(string path)
  {
    LocalFiles.CheckLinks(path);
    var acl = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
    Protocol.Require(User.Equals(acl.GetOwner(typeof(SecurityIdentifier))), "directory-owner-mismatch");
    foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
      Protocol.Require(rule.AccessControlType != AccessControlType.Allow || rule.IdentityReference.Equals(User) || rule.IdentityReference.Equals(SystemUser), "directory-permissions-too-broad");
  }

  public void ValidateTree(string root)
  {
    ValidatePrivateDirectory(root);
    foreach (var path in Directory.EnumerateFileSystemEntries(root))
    {
      LocalFiles.CheckLinks(path);
      if (Directory.Exists(path)) ValidateTree(path);
      else
      {
        var acl = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        Protocol.Require(User.Equals(acl.GetOwner(typeof(SecurityIdentifier))), "file-owner-mismatch");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
          Protocol.Require(rule.AccessControlType != AccessControlType.Allow || rule.IdentityReference.Equals(User) || rule.IdentityReference.Equals(SystemUser), "file-permissions-too-broad");
      }
    }
  }

  public string DirectoryIdentity(string path)
  {
    LocalFiles.CheckLinks(path);
    // Query metadata only: OPEN_EXISTING cannot create/truncate the directory. BackupSemantics
    // allows a directory handle; OpenReparsePoint avoids following a final-component link.
    // It does not enable backup privileges. SafeFileHandle owns and closes the native handle.
    using var handle = CreateFileW(path, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
      FileMode.Open, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
    if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info))
      throw new BrokerException("directory-identity-unavailable");
    Protocol.Require((info.Attributes & (uint)FileAttributes.Directory) != 0 &&
      (info.Attributes & (uint)FileAttributes.ReparsePoint) == 0, "directory-identity-unavailable");
    return $"{info.VolumeSerialNumber:x8}:{info.FileIndexHigh:x8}{info.FileIndexLow:x8}";
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct FileInformation
  {
    public uint Attributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
    public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
  }
  private const uint FileFlagBackupSemantics = 0x02000000;
  private const uint FileFlagOpenReparsePoint = 0x00200000;
  [DllImport("kernel32.dll", EntryPoint = "CreateFileW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle CreateFileW(string name, uint access, FileShare share, IntPtr security, FileMode disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
}
