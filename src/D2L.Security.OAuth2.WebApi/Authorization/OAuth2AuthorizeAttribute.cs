using System.Linq;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace D2L.Security.OAuth2.Authorization {
	public abstract class OAuth2AuthorizeAttribute : AuthorizeAttribute {

		private const string AUTH_HAS_RUN = "D2L.Security.OAuth2.Authorization.OAuth2AuthorizeAttribute_Auth_Has_Run";
		private const string FAILING_ATTR_PROP = "D2L.Security.OAuth2.Authorization.OAuth2AuthorizeAttribute_Failing_Attribute";

		protected override bool IsAuthorized( HttpActionContext actionContext ) {
			var props = actionContext.Request.Properties;
			if( props.ContainsKey( AUTH_HAS_RUN ) ) {
				return true;
			}

			props[ AUTH_HAS_RUN ] = true;

			var actionAttributes = actionContext
				.ActionDescriptor
				.GetCustomAttributes<OAuth2AuthorizeAttribute>( inherit: true );
			var actionAttributeTypes = actionAttributes
				.Select( x => x.GetType() );
			var controllerAttributes = actionContext
				.ActionDescriptor
				.ControllerDescriptor
				.GetCustomAttributes<OAuth2AuthorizeAttribute>( inherit: true );

			var oauth2Attributes = actionAttributes
				.Union( controllerAttributes.Where( x => !actionAttributeTypes.Contains( x.GetType() ) ) )
				.OrderBy( x => x.Order )
				.ToArray();

			foreach( var attr in oauth2Attributes ) {
				if( !attr.IsAuthorizedInternal( actionContext ) ) {
					props[ FAILING_ATTR_PROP ] = attr;
					return false;
				}
			}

			return true;
		}

		protected override void HandleUnauthorizedRequest( HttpActionContext actionContext ) {
			var props = actionContext.Request.Properties;

			var attr = (OAuth2AuthorizeAttribute)props[ FAILING_ATTR_PROP ];

			attr.HandleUnauthorizedRequestInternal( actionContext );
		}

		protected virtual void HandleUnauthorizedRequestInternal( HttpActionContext actionContext ) {
			base.HandleUnauthorizedRequest( actionContext );
		}

		protected abstract uint Order { get; }

		protected abstract bool IsAuthorizedInternal( HttpActionContext actionContext );

	}
}
