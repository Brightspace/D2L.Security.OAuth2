﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Principal {
	[Immutable]
	internal sealed class AnonymousPrincipal : ID2LPrincipal {

		private static readonly IAccessToken ANONYMOUS_ACCESS_TOKEN = new AnonymousAccessToken();

		long ID2LPrincipal.UserId {
			get { throw new InvalidOperationException( "Cannot access UserId for an Anonymous Principal" ); }
		}

		long ID2LPrincipal.ActualUserId {
			get { throw new InvalidOperationException( "Cannot access ActualUserId for an Anonymous Principal" ); }
		}

		Guid ID2LPrincipal.TenantId {
			get { throw new InvalidOperationException( "Cannot access TenantId for an Anonymous Principal" ); }
		}

		PrincipalType ID2LPrincipal.Type {
			get { return PrincipalType.Anonymous; }
		}

		IEnumerable<Scope> ID2LPrincipal.Scopes {
			get { return Enumerable.Empty<Scope>(); }
		}

		IAccessToken ID2LPrincipal.AccessToken {
			get { return ANONYMOUS_ACCESS_TOKEN; }
		}

		[Immutable]
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
