using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {
	/// <summary>
	/// This class can serve as either an IPrincipal or an ID2LPrincipal
	/// </summary>
	internal sealed class D2LPrincipalToIPrincipalAdaptor : IPrincipal, ID2LPrincipal {
		private readonly ID2LPrincipal m_principal;

		public D2LPrincipalToIPrincipalAdaptor( ID2LPrincipal principal ) {
			m_principal = principal;
		}

		IAccessToken ID2LPrincipal.AccessToken {
			get { return m_principal.AccessToken; }
		}

		IEnumerable<Scope> ID2LPrincipal.Scopes {
			get { return m_principal.Scopes; }
		}

		Guid ID2LPrincipal.TenantId {
			get { return m_principal.TenantId; }
		}
		
		PrincipalType ID2LPrincipal.Type {
			get { return m_principal.Type; }
		}

		string ID2LPrincipal.UserId {
			get { return m_principal.UserId; }
		}

		public IIdentity Identity {
			get { throw new NotImplementedException(); }
		}

		public bool IsInRole( string role ) {
			throw new NotImplementedException();
		}
	}
}
