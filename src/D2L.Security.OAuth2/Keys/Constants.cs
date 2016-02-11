using System;
namespace D2L.Security.OAuth2.Keys {
	internal static class Constants {

		internal const int GENERATED_RSA_KEY_SIZE = 2048;

		internal static readonly TimeSpan DEFAULT_KEY_LIFETIME = TimeSpan.FromHours( 1 );
		internal static readonly TimeSpan DEFAULT_KEY_ROTATION_PERIOD = TimeSpan.FromMinutes( 10 );

		// Keys are good for one hour from when they are fetched
		internal static readonly TimeSpan REMOTE_KEY_MAX_LIFETIME = TimeSpan.FromHours( 1 );
	}
}
