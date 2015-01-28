using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using D2L.Security.RequestAuthentication;

namespace D2L.Security.WebApiAuth.Principal {

	/// <summary>
	/// This class has some ugliness to present a clean injectable principal. It uses a lazy cache
	/// to delay fetching the principal from the current thread context, because it is not available 
	/// at the time the principal is injected, which is before the authentication message handler and 
	/// controller are even created.
	/// </summary>
	public sealed class D2LPrincipalAdapter : ID2LPrincipalAdapter {

		private readonly Lazy<ID2LPrincipal> m_principal;

		public D2LPrincipalAdapter() {
			m_principal = new Lazy<ID2LPrincipal>( GetCurrentPrincipal );
		}

		#region ID2LPrincipal Passthrough Members

		PrincipalType ID2LPrincipal.Type {
			get { return m_principal.Value.Type; }
		}

		IEnumerable<string> ID2LPrincipal.Scopes {
			get { return m_principal.Value.Scopes; }
		}

		DateTime ID2LPrincipal.SecurityExpiry {
			get { return m_principal.Value.SecurityExpiry; }
		}

		string ID2LPrincipal.Xsrf {
			get { return m_principal.Value.Xsrf; }
		}

		string ID2LPrincipal.AccessToken {
			get { return m_principal.Value.AccessToken; }
		}

		long? ID2LPrincipal.UserId {
			get { return m_principal.Value.UserId; }
		}

		string ID2LPrincipal.TenantId {
			get { return m_principal.Value.TenantId; }
		}

		string ID2LPrincipal.TenantUrl {
			get { return m_principal.Value.TenantUrl; }
		}

		#endregion ID2LPrincipal Passthrough Members

		#region IPrincipal Members (Not Implemented)

		/// <summary>
		/// Do not use. Throws NotImplementedException.
		/// </summary>
		bool IPrincipal.IsInRole( string role ) {
			throw new NotImplementedException();
		}

		/// <summary>
		/// Do not use. Returns null.
		/// </summary>
		/// <remarks>Null due to logging framework attempting to access the principal.</remarks>
		IIdentity IPrincipal.Identity {
			get { return null; }
		}

		#endregion IPrincipal Members (Not Implemented)

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
	}
}
