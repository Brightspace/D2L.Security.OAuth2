using System;
using System.Collections.Generic;
using System.Security.Principal;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {
	/// <summary>
	/// This class can serve as either an IPrincipal or an ID2LPrincipal
	/// </summary>
	internal sealed class D2LPrincipalToIPrincipalAdaptor : IPrincipal, ID2LPrincipal {
		private readonly ID2LPrincipal m_principal;
		[Mutability.Audited( "Todd Lang", "02-Mar-2018", ".Net class can't modify, but is immutable." )]
		private readonly IIdentity m_identity;

		public D2LPrincipalToIPrincipalAdaptor( ID2LPrincipal principal ) {
			m_principal = principal;

			// This is required for the IIS hosted services (WebHost)
			// We aren't honestly using this functionality at the moment.
			// TODO: validate that IIS uses this e.g. to fill out logs
			m_identity = new GenericIdentity(
				name: "D2LPrincipalToIPrincipalAdaptor_" + Guid.NewGuid().ToString()
			);
		}

		IAccessToken ID2LPrincipal.AccessToken {
			get { return m_principal.AccessToken; }
		}

		long ID2LPrincipal.ActualUserId {
			get { return m_principal.ActualUserId; }
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

		long ID2LPrincipal.UserId {
			get { return m_principal.UserId; }
		}

		IIdentity IPrincipal.Identity {
			get { return m_identity; }
		}

		bool IPrincipal.IsInRole( string role ) {
			// We aren't usefully implementing IPrincipal at this point
			return false;
		}
	}
}
