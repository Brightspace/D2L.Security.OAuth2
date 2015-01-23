using System;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuthFilter {

	public static class AuthenticationConfig {

		/// <summary>
		/// Call this method only once and before the service begins listening.
		/// </summary>
		/// <param name="authServiceEndpoint">Used to fetch the certificate to validate the signature of
		/// the token. For testing, set to null to bypass authentication altogether.</param>
		/// <param name="logProvider">Specifiy NullLogProvider.Instance if no logger is available.</param>
		/// <remarks>Because of this function, test parallelization by consuming projects is inhibited.</remarks>
		public static void Initialize(
			Uri authServiceEndpoint,
			ILogProvider logProvider
			) {

			AuthServiceEndpoint = authServiceEndpoint;
			LogProvider = logProvider;
		}

		public static ILogProvider LogProvider { get; private set; }
		public static Uri AuthServiceEndpoint { get; private set; }
	}
}
