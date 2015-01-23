using System.Net.Http;
using System.Web;
using D2L.Security.RequestAuthentication;

namespace D2L.Security.WebApiAuthFilter {

	/// <summary>
	/// A convenience class used for testing that returns a null IGenericPrincipal.
	/// </summary>
	internal sealed class NullRequestAuthenticator : IRequestAuthenticator {

		public static IRequestAuthenticator Instance { get; private set; }

		static NullRequestAuthenticator() {
			Instance = new NullRequestAuthenticator();
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract(
			HttpRequestMessage request,
			out ID2LPrincipal principal
			) {

			principal = null;
			return AuthenticationResult.Success;
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract(
			HttpRequest request,
			out ID2LPrincipal principal
			) {

			principal = null;
			return AuthenticationResult.Success;
		}
	}
}
