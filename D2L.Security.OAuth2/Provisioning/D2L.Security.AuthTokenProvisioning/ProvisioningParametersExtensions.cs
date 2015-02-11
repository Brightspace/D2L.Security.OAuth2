using D2L.Security.AuthTokenProvisioning.Invocation;

namespace D2L.Security.AuthTokenProvisioning {
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
