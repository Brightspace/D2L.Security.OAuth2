using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	/// <summary>
	/// Restrict which kinds of authenticated users are authorized to use these APIs
	/// </summary>
	[AttributeUsage( AttributeTargets.All, AllowMultiple = false )]
	public sealed class AuthenticationAttribute : AuthorizeAttribute {

		private readonly PrincipalType m_allowedPrincipalTypes;

		/// <summary>
		/// Restrict an API to users, services or both.
		/// </summary>
		/// <param name="allowedPrincipalTypes">The types of callers that are allowed to call this API</param>
		public AuthenticationAttribute(
			PrincipalType allowedPrincipalTypes
		) {
			if( ( m_allowedPrincipalTypes & PrincipalType.Anonymous ) == PrincipalType.Anonymous ) {
				if ( m_allowedPrincipalTypes != PrincipalType.Anonymous ) {
					throw new ArgumentException( "Anonymous is mutually exclusive with the other types of principal" );
				}
			}
			m_allowedPrincipalTypes = allowedPrincipalTypes;
		}

		protected override bool IsAuthorized( HttpActionContext context ) {
			var principal = context.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			if( m_allowedPrincipalTypes == PrincipalType.Anonymous ) {
				return true;
			}

			return ( m_allowedPrincipalTypes & principal.Type ) == principal.Type;
		}
	}
}
