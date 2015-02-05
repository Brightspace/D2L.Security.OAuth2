using System;

namespace D2L.Security.BrowserAuthTokens {
	internal static class DateTimeExtensions {

		private static readonly DateTime UNIX_EPOCH_START = 
			new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc );

		/// <param name="date">The date</param>
		/// <returns>Number of seconds since the beginning of the Unix Epoch to the specified date</returns>
		internal static long GetSecondsSinceUnixEpoch( this DateTime date ) {
			TimeSpan sinceUnixEpoch = date - UNIX_EPOCH_START;
			return (long)sinceUnixEpoch.TotalSeconds;
		}
	}
}
