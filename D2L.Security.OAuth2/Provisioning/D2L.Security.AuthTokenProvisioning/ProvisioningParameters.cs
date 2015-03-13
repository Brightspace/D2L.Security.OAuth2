using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using D2L.Security.AuthTokenProvisioning.Invocation;

namespace D2L.Security.AuthTokenProvisioning {

	/// <summary>
	/// Configures an assertion grant provisioning
	/// </summary>
	public sealed class ProvisioningParameters {
		
		private readonly IEnumerable<string> m_scopes;

		private readonly string m_tenantId;
		private readonly string m_tenantUrl;
		private readonly DateTime m_expiry;

		private readonly RSA m_signingKey;

		public ProvisioningParameters( 
			IEnumerable<string> scopes, 
			string tenantId,
			string tenantUrl,
			RSA signingKey
			) {

			m_scopes = scopes;
			m_tenantId = tenantId;
			m_tenantUrl = tenantUrl;
			m_signingKey = signingKey;

			m_expiry = DateTime.UtcNow + Constants.AssertionGrant.ASSERTION_TOKEN_LIFETIME;
		}

		public string UserId { get; set; }
		public string Xsrf { get; set; }
		
		public IEnumerable<string> Scopes {
			get { return m_scopes; }
		}

		public string TenantId {
			get { return m_tenantId; }
		}

		public string TenantUrl {
			get { return m_tenantUrl; }
		}

		public DateTime Expiry {
			get { return m_expiry; }
		}

		public RSA SigningKey {
			get { return m_signingKey; }
		}

		internal InvocationParameters ToInvocationParameters(
			string assertionToken
			) {

			InvocationParameters result = new InvocationParameters(
				Scopes,
				assertionToken
				);

			return result;
		}
	}
}
