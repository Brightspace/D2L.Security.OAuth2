using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Authorization.Exceptions;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Authorization {
	public abstract class OAuth2AuthorizeAttribute : AuthorizeAttribute {

		private const string AUTH_HAS_RUN = "D2L.Security.OAuth2.Authorization.OAuth2AuthorizeAttribute_Auth_Has_Run";
		private const string FAILED_EXCEPTION_PROP = "D2L.Security.OAuth2.Authorization.OAuth2AuthorizeAttribute_Failed_Exception";

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
				try {
					if( !attr.IsAuthorizedInternal( actionContext ) ) {
						return false;
					}
				} catch( OAuth2Exception e ) {
					props[ FAILED_EXCEPTION_PROP ] = e;
					return false;
				}
			}

			return true;
		}

		protected override void HandleUnauthorizedRequest( HttpActionContext actionContext ) {
			var props = actionContext.Request.Properties;

			if( !props.TryGetValue( FAILED_EXCEPTION_PROP, out object exceptionObj ) ) {
				HandleNoAuth( actionContext );
				return;
			}

			OAuth2Exception exception = exceptionObj as OAuth2Exception;
			OAuth2ErrorResponse responseContent = new OAuth2ErrorResponse(
				error: exception.Error.ToString(),
				errorDescription: exception.ErrorDescription
			);
			string authenticateHeader = $"Bearer error=\"{ responseContent.Error }\", error_description=\"{ responseContent.ErrorDescription }\"";

			if( exception is InsufficientScopeException insufficientScopeException ) {
				responseContent.Scope = insufficientScopeException.Scope.ToString();
				authenticateHeader += $", scope=\"{ responseContent.Scope }\"";
			}

			var response = new HttpResponseMessage( (HttpStatusCode)exception.Error ) {
				Content = new ObjectContent<OAuth2ErrorResponse>(
					responseContent,
					new JsonMediaTypeFormatter() {
						SerializerSettings = new JsonSerializerSettings() {
							NullValueHandling = NullValueHandling.Ignore
						}
					}
				)
			};
			response.Headers.Add( "WWW-Authenticate", authenticateHeader );

			actionContext.Response = response;
		}

		protected virtual void HandleUnauthorizedRequestInternal( HttpActionContext actionContext ) {
			base.HandleUnauthorizedRequest( actionContext );
		}

		protected abstract uint Order { get; }

		protected abstract bool IsAuthorizedInternal( HttpActionContext actionContext );

		private static void HandleNoAuth( HttpActionContext actionContext ) {
			var response = new HttpResponseMessage( HttpStatusCode.Unauthorized );
			response.Headers.Add( "WWW-Authenticate", "Bearer" );

			actionContext.Response = response;
		}

	}
}
