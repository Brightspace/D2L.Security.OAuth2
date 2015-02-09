using System;
using System.Collections.Generic;

namespace D2L.Security.BrowserAuthTokens {

	/// <summary>
	/// Configures assertion grant token
	/// </summary>
	public sealed class ProvisioningParameters {

		private readonly string m_clientId;
		private readonly string m_clientSecret;
		private readonly IEnumerable<string> m_scopes;

		private readonly string m_tenantId;
		private readonly string m_tenantUrl;
		private readonly DateTime m_expiry;

		public ProvisioningParameters( 
			string clientId, 
			string clientSecret, 
			IEnumerable<string> scopes, 
			string tenantId,
			string tenantUrl
			) {

			m_clientId = clientId;
			m_clientSecret = clientSecret;
			m_scopes = scopes;
			m_tenantId = tenantId;
			m_tenantUrl = tenantUrl;

			m_expiry = DateTime.UtcNow + Constants.AssertionGrant.ASSERTION_TOKEN_LIFETIME;
		}

		public string UserId { get; set; }
		public string Xsrf { get; set; }

		public string ClientId {
			get { return m_clientId; }
		}

		public string ClientSecret {
			get { return m_clientSecret; }
		}

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
	}
}
