using System;
using System.Collections.Generic;
using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal sealed class ValidatedTokenToD2LPrincipalAdapter : ID2LPrincipal {

		private readonly DateTime m_expiry;
		private readonly long? m_userId;
		private readonly string m_tenantId;
		private readonly IEnumerable<string> m_scopes;
		private readonly PrincipalType m_type;
		
		private readonly string m_xsrf;
		private readonly string m_accessToken;

		internal ValidatedTokenToD2LPrincipalAdapter( IValidatedToken validatedToken, string accessToken ) {
			m_expiry = validatedToken.Expiry;
			m_tenantId = validatedToken.GetTenantId();
			m_scopes = validatedToken.GetScopes();

			m_userId = validatedToken.GetUserId();
			m_type = m_userId.HasValue ? PrincipalType.User : PrincipalType.Service;

			m_xsrf = validatedToken.GetXsrfToken();
			m_accessToken = accessToken;
		}

		DateTime ID2LPrincipal.SecurityExpiry {
			get { return m_expiry; }
		}

		long? ID2LPrincipal.UserId {
			get { return m_userId; }
		}
		
		string ID2LPrincipal.TenantId {
			get { return m_tenantId; }
		}

		string ID2LPrincipal.TenantUrl {
			get { throw new NotImplementedException(); }
		}
		
		IEnumerable<string> ID2LPrincipal.Scopes {
			get { return m_scopes; }
		}

		PrincipalType ID2LPrincipal.Type {
			get { return m_type; }
		}

		string ID2LPrincipal.Xsrf {
			get { return m_xsrf;  }
		}

		string ID2LPrincipal.AccessToken {
			get { return m_accessToken; }
		}
	}
}
