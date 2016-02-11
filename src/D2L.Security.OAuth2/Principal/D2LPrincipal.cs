using System;
using System.Collections.Generic;
using System.Linq;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {

	internal sealed class D2LPrincipal : ID2LPrincipal {

		private readonly IAccessToken m_accessToken;

		private readonly string m_userId;
		private readonly Lazy<Guid> m_tenantId;
		private readonly PrincipalType m_principalType;
		private readonly Lazy<List<Scope>> m_scopes;

		public D2LPrincipal( IAccessToken accessToken ) {
			m_accessToken = accessToken;

			m_userId = accessToken.GetUserId();
			m_tenantId = new Lazy<Guid>( GetTenantId );
			m_principalType = string.IsNullOrEmpty( m_userId ) ? PrincipalType.Service : PrincipalType.User;
			m_scopes = new Lazy<List<Scope>>( () => m_accessToken.GetScopes().ToList() );
		}

		private Guid GetTenantId() {
			string strTenantId = m_accessToken.GetTenantId();

			Guid tenantId;
			if( !Guid.TryParse( strTenantId, out tenantId ) ) {
				string message = string.Format( "TenantId '{0}' is not a valid Guid", strTenantId );
				throw new Exception( message );
			}
			return tenantId;
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

		Guid ID2LPrincipal.TenantId {
			get { return m_tenantId.Value; }
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
