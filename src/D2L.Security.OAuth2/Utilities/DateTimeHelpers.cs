using System;

namespace D2L.Security.OAuth2 {
	internal static class DateTimeHelpers {
		public static readonly DateTime EPOCH = new DateTime( 1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc );

		public static DateTime FromUnixTime( long seconds ) {
			return EPOCH.AddSeconds( seconds );
		}
	}
}
