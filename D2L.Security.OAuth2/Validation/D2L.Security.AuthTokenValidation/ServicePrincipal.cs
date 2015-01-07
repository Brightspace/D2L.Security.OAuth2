using System.Collections.Generic;

namespace D2L.Security.AuthTokenValidation {

	internal sealed class ServicePrinciple : Principal {

		public ServicePrinciple(
			string clientId,
			HashSet<string> scopes
			) {

			ClientId = clientId;
			Scopes = scopes;
		}

		public string ClientId { get; private set; }
	}
}