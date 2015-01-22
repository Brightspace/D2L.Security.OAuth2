using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;

namespace D2L.Security.WebApiAuthFilter {

	/// <summary>
	/// This class has some ugliness to present a clean injectable principal. It uses a lazy cache
	/// to delay fetching the principal from the current thread context, because it is not available 
	/// at the time the principal is injected, which is before the authentication filter and 
	/// controller are even created.
	/// </summary>
	internal sealed class D2LPrincipal : ID2LPrincipal {

		private readonly Lazy<IGenericPrincipal> m_principal;

		public D2LPrincipal() {
			m_principal = new Lazy<IGenericPrincipal>( GetCurrentPrincipal );
		}

		bool IPrincipal.IsInRole( string role ) {
			return m_principal.Value.IsInRole( role );
		}

		IIdentity IPrincipal.Identity {
			get { return m_principal.Value.Identity; }
		}

		bool IGenericPrincipal.HasScope( string scope ) {
			return m_principal.Value.HasScope( scope );
		}

		void IGenericPrincipal.AssertScope( string scope ) {
			m_principal.Value.AssertScope( scope );
		}

		HashSet<string> IGenericPrincipal.Scopes {
			get { return m_principal.Value.Scopes; }
		}

		long IGenericPrincipal.UserId {
			get { return m_principal.Value.UserId; }
		}

		string IGenericPrincipal.TenantId {
			get { return m_principal.Value.TenantId; }
		}

		string IGenericPrincipal.XsrfToken {
			get { return m_principal.Value.XsrfToken; }
		}

		bool IGenericPrincipal.IsBrowserUser {
			get { return m_principal.Value.IsBrowserUser; }
		}

		/// <summary>
		/// Gets the principal from the current thread context, as assigned by the auth filter.
		/// This method depends on the principal being assigned before this method executes.
		/// </summary>
		/// <returns>The principal object</returns>
		private IGenericPrincipal GetCurrentPrincipal() {

			if( !( Thread.CurrentPrincipal is IGenericPrincipal ) ) {
				throw new Exception( "D2LPrincipal has not been assigned" );
			}

			return (IGenericPrincipal)Thread.CurrentPrincipal;
		}
	}
}
