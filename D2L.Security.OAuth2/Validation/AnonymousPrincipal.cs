using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Validation {
	internal sealed class AnonymousPrincipal : ID2LPrincipal {

		private readonly IEnumerable<Claim> m_claims;
		private readonly IEnumerable<Scope> m_scopes;

		public AnonymousPrincipal() {
			m_claims = Enumerable.Empty<Claim>();
			m_scopes = Enumerable.Empty<Scope>();
		}

		public string UserId {
			get { throw new InvalidOperationException( "Cannot access UserId for an Anonymous Principal" ); }
		}

		public string TenantId {
			get { throw new InvalidOperationException( "Cannot access TenantId for an Anonymous Principal" ); }
		}

		public PrincipalType Type {
			get { return PrincipalType.Anonymous; }
		}

		public IEnumerable<Scope> Scopes {
			get { return m_scopes; }
		}

		public IEnumerable<Claim> AllClaims {
			get { return m_claims; }
		}

		public DateTime AccessTokenExpiry {
			get { return DateTime.Now.AddHours( 1 ); }
		}

		public string Xsrf {
			get { return ""; }
		}

		public string AccessToken {
			get { return ""; }
		}

		public string AccessTokenId {
			get { return ""; }
		}
	}
}
