using System;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuthFilter {

	public static class AuthenticationConfig {

		/// <summary>
		/// Call this method only once before the
		/// </summary>
		/// <param name="authServiceEndpoint">Used to fetch the certificate to validate the signature of
		/// the token. For testing, set to null to bypass authentication altogether.</param>
		/// <param name="logProvider">Specifiy NullLogProvider.Instance if no logger is available.</param>
		public static void Initialize(
			Uri authServiceEndpoint,
			ILogProvider logProvider
			) {

			if( LogProvider != null ) {
				throw new InvalidOperationException( "Initialize has already been called." );
			}

			AuthServiceEndpoint = authServiceEndpoint;
			LogProvider = logProvider;
		}

		public static ILogProvider LogProvider { get; private set; }
		public static Uri AuthServiceEndpoint { get; private set; }
	}
}
