using D2L.Security.BrowserAuthTokens.Invocation;

namespace D2L.Security.BrowserAuthTokens {
	internal static class ProvisioningParametersExtensions {

		internal static InvocationParameters ToInvocationParameters( 
			this ProvisioningParameters me, 
			string assertionToken 
			) {

			InvocationParameters result = new InvocationParameters(
				me.ClientId,
				me.ClientSecret,
				me.Scopes,
				assertionToken
				);

			return result;
		}
	}
}
