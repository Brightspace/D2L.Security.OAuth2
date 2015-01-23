using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using D2L.Security.RequestAuthentication;

namespace D2L.Security.WebApiAuthFilter {

	/// <summary>
	/// This class has some ugliness to present a clean injectable principal. It uses a lazy cache
	/// to delay fetching the principal from the current thread context, because it is not available 
	/// at the time the principal is injected, which is before the authentication filter and 
	/// controller are even created.
	/// </summary>
	public sealed class D2LPrincipalAdapter : ID2LPrincipalAdapter {

		private readonly Lazy<ID2LPrincipal> m_principal;

		public D2LPrincipalAdapter() {
			m_principal = new Lazy<ID2LPrincipal>( GetCurrentPrincipal );
		}

		public bool IsService {
			get { return m_principal.Value.IsService; }
		}

		IEnumerable<string> ID2LPrincipal.Scopes {
			get { return m_principal.Value.Scopes; }
		}

		long? ID2LPrincipal.UserId {
			get { return m_principal.Value.UserId; }
		}

		string ID2LPrincipal.ClientId {
			get { return m_principal.Value.ClientId; }
		}

		string ID2LPrincipal.TenantId {
			get { return m_principal.Value.TenantId; }
		}

		string ID2LPrincipal.TenantUrl {
			get { return m_principal.Value.TenantUrl; }
		}

		bool ID2LPrincipal.XsrfSafe {
			get { return m_principal.Value.XsrfSafe; }
		}

		bool ID2LPrincipal.IsBrowserUser {
			get { return m_principal.Value.IsBrowserUser; }
		}

		/// <summary>
		/// Do not use. Throws NotImplementedException.
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
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

		/// <summary>
		/// Gets the principal from the current thread context, as assigned by the auth filter.
		/// This method depends on the principal being assigned before this method executes.
		/// </summary>
		/// <returns>The principal object.</returns>
		private ID2LPrincipal GetCurrentPrincipal() {

			if( !( Thread.CurrentPrincipal is ID2LPrincipal ) ) {
				throw new PrincipalNotAssignedException( "ID2LPrincipal has not been assigned" );
			}

			return (ID2LPrincipal)Thread.CurrentPrincipal;
		}
	}
}
