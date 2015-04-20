using System;
using System.Collections.Generic;
using System.Linq;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {

	internal sealed class D2LPrincipal : ID2LPrincipal {

		private readonly IAccessToken m_accessToken;

		private readonly string m_userId;
		private readonly string m_tenantId;
		private readonly PrincipalType m_principalType;
		private readonly Lazy<List<Scope>> m_scopes;

		public D2LPrincipal( IAccessToken accessToken ) {
			m_accessToken = accessToken;

			m_userId = accessToken.GetUserId();
			m_tenantId = accessToken.GetTenantId();
			m_principalType = string.IsNullOrEmpty( m_userId ) ? PrincipalType.Service : PrincipalType.User;
			m_scopes = new Lazy<List<Scope>>( () => m_accessToken.GetScopes().ToList() );
		}

		string ID2LPrincipal.UserId {
			get {
				if( m_principalType != PrincipalType.User ) {
					string message = string.Format(
						"Cannot access UserId for principal type: {0}",
						m_principalType
					);
					throw new InvalidOperationException( message );
				}
				return m_userId;
			}
		}

		string ID2LPrincipal.TenantId {
			get { return m_tenantId; }
		}

		PrincipalType ID2LPrincipal.Type {
			get { return m_principalType; }
		}

		IEnumerable<Scope> ID2LPrincipal.Scopes {
			get { return m_scopes.Value; }
		}

		IAccessToken ID2LPrincipal.AccessToken {
			get { return m_accessToken; }
		}
		
	}
}
