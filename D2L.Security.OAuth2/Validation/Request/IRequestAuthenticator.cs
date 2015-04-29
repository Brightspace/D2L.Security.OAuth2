using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;

namespace D2L.Security.OAuth2.Validation.Request {
	public interface IRequestAuthenticator {
		Task<AuthenticationResponse> AuthenticateAsync(
			Uri authEndpoint,
			HttpRequestMessage request,
			AuthenticationMode authMode = AuthenticationMode.Full
		);

		Task<AuthenticationResponse> AuthenticateAsync(
			Uri authEndpoint,
			HttpRequest request,
			AuthenticationMode authMode = AuthenticationMode.Full
		);
	}
}
