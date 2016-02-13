using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {

	/// <summary>
	/// This class has some ugliness to present a clean injectable principal. It uses a lazy cache
	/// to delay fetching the principal from the current thread context, because it is not available 
	/// at the time the principal is injected, which is before the authentication message handler and 
	/// controller are even created.
	/// </summary>
	public sealed class D2LPrincipalAdapter : ClaimsPrincipal, ID2LPrincipal {

		private readonly Lazy<ID2LPrincipal> m_principal;

		#region Constructors

		public D2LPrincipalAdapter() {
			m_principal = new Lazy<ID2LPrincipal>( GetCurrentPrincipal );
		}

		internal D2LPrincipalAdapter( ID2LPrincipal principal ) {
			m_principal = new Lazy<ID2LPrincipal>( () => principal );
		}

		#endregion Constructors

		#region ID2LPrincipal Passthrough Members

		IAccessToken ID2LPrincipal.AccessToken {
			get { return m_principal.Value.AccessToken; }
		}

		IEnumerable<Scope> ID2LPrincipal.Scopes {
			get { return m_principal.Value.Scopes; }
		}

		Guid ID2LPrincipal.TenantId {
			get { return m_principal.Value.TenantId; }
		}
		
		PrincipalType ID2LPrincipal.Type {
			get { return m_principal.Value.Type; }
		}

		string ID2LPrincipal.UserId {
			get { return m_principal.Value.UserId; }
		}
		
		#endregion ID2LPrincipal Passthrough Members

		public override IEnumerable<Claim> Claims {
			get {
				return m_principal.Value.AccessToken.Claims;
			}
		}

		public override IEnumerable<ClaimsIdentity> Identities {
			get {
				ClaimsIdentity identity = new ClaimsIdentity( Claims );
				return new ClaimsIdentity[] { identity };
			}
		}

		public override bool IsInRole( string role ) {
			throw new NotImplementedException();
		}

		#region Private Methods

		/// <summary>
		/// Gets the principal from the current thread context, as assigned by the auth message handler.
		/// This method depends on the principal being assigned before this method executes.
		/// </summary>
		/// <returns>The principal object.</returns>
		private ID2LPrincipal GetCurrentPrincipal() {

			if( !( Thread.CurrentPrincipal is ID2LPrincipal ) ) {
				throw new PrincipalNotAssignedException( "Principal must be assigned to Thread.CurrentPrincipal before accessing properties" );
			}

			return (ID2LPrincipal)Thread.CurrentPrincipal;
		}

		#endregion Private Methods
	}
}
