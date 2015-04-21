using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {
	internal sealed class AnonymousPrincipal : ID2LPrincipal {

		private static readonly IAccessToken ANONYMOUS_ACCESS_TOKEN = new AnonymousAccessToken();

		private readonly IEnumerable<Scope> m_scopes;
		
		public AnonymousPrincipal() {
			m_scopes = Enumerable.Empty<Scope>();
		}

		string ID2LPrincipal.UserId {
			get { throw new InvalidOperationException( "Cannot access UserId for an Anonymous Principal" ); }
		}

		Guid ID2LPrincipal.TenantId {
			get { throw new InvalidOperationException( "Cannot access TenantId for an Anonymous Principal" ); }
		}

		PrincipalType ID2LPrincipal.Type {
			get { return PrincipalType.Anonymous; }
		}

		IEnumerable<Scope> ID2LPrincipal.Scopes {
			get { return m_scopes; }
		}

		IAccessToken ID2LPrincipal.AccessToken {
			get { return ANONYMOUS_ACCESS_TOKEN; }
		}

		private class AnonymousAccessToken : IAccessToken {

			string IAccessToken.Id {
				get { return ""; }
			}

			IEnumerable<Claim> IAccessToken.Claims {
				get { return Enumerable.Empty<Claim>(); }
			} 

			string IAccessToken.SensitiveRawAccessToken {
				get { return ""; }
			}

			DateTime IAccessToken.Expiry {
				get { return DateTime.MaxValue; }
			}
		}


	}
}
