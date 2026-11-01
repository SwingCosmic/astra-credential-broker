using Microsoft.Data.Sqlite;

namespace Astra.Credentials;

public sealed class Database : IDisposable
{
  public SqliteConnection Connection { get; }
  public Database(string path, bool create = true)
  {
    LocalFiles.CheckLinks(path);
    Connection = new SqliteConnection(new SqliteConnectionStringBuilder
    { DataSource = path, Mode = create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
    Connection.Open();
    Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
  }
  public void Execute(string sql, params (string Name, object? Value)[] args)
  {
    using var cmd = Command(sql, args);
    cmd.ExecuteNonQuery();
  }
  public object? Scalar(string sql, params (string Name, object? Value)[] args)
  {
    using var cmd = Command(sql, args);
    return cmd.ExecuteScalar();
  }
  public List<T> Rows<T>(string sql, Func<SqliteDataReader, T> read, params (string Name, object? Value)[] args)
  {
    using var cmd = Command(sql, args);
    using var reader = cmd.ExecuteReader();
    var result = new List<T>();
    while (reader.Read()) result.Add(read(reader));
    return result;
  }
  public T Atomic<T>(Func<T> work)
  {
    Execute("BEGIN IMMEDIATE");
    try
    {
      var value = work();
      Execute("COMMIT");
      return value;
    }
    catch { Execute("ROLLBACK"); throw; }
  }
  private SqliteCommand Command(string sql, (string Name, object? Value)[] args)
  {
    var cmd = Connection.CreateCommand();
    cmd.CommandText = sql;
    foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
    return cmd;
  }
  public void Dispose() => Connection.Dispose();
}
