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
	public sealed class AuthenticationAttribute : OAuth2AuthorizeAttribute {
		private readonly bool m_allowUsers;
		private readonly bool m_allowServices;

		/// <summary>
		/// Restrict an API to users, services or both.
		/// </summary>
		/// <param name="users">Requests with a user context</param>
		/// <param name="services">Requests without a user context</param>
		public AuthenticationAttribute(
			bool users = false,
			bool services = false
		) {
			if( !users && !services ) {
				throw new ArgumentException( "You must allow for at least one of users or services. If you want to allow anonymous users use [AllowAnonymous] instead" );
			}

			m_allowUsers = users;
			m_allowServices = services;
		}

		protected override uint Order {
			get {
				return 0;
			}
		}

		protected override bool IsAuthorizedInternal( HttpActionContext context ) {
			var principal = context.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			switch( principal.Type ) {
				case PrincipalType.Anonymous:
					return false;

				case PrincipalType.User:
					return m_allowUsers;

				case PrincipalType.Service:
					return m_allowServices;

				default:
					throw new NotImplementedException();
			}
		}
	}
}
