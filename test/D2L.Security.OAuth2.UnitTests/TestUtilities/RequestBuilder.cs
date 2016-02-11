using System;
using System.Collections;
using System.Collections.Specialized;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Web;
using D2L.Security.OAuth2.Validation.Request;

namespace D2L.Security.OAuth2.TestUtilities {
	internal static class RequestBuilder {
		#region HttpRequestMessage
		
		internal static HttpRequestMessage WithAuthHeader( this HttpRequestMessage httpRequestMessage, string authHeaderValue ) {
			return httpRequestMessage.WithAuthHeader( RequestValidationConstants.BearerTokens.SCHEME, authHeaderValue );
		}

		internal static HttpRequestMessage WithAuthHeader( this HttpRequestMessage httpRequestMessage, string scheme, string authHeaderValue ) {
			var authHeaderVal = new AuthenticationHeaderValue( scheme, authHeaderValue );
			httpRequestMessage.Headers.Authorization = authHeaderVal;
			return httpRequestMessage;
		}

		internal static HttpRequestMessage WithXsrfHeader( this HttpRequestMessage httpRequestMessage, string xsrfHeaderValue ) {
			httpRequestMessage.Headers.Add( RequestValidationConstants.Headers.XSRF, xsrfHeaderValue );
			return httpRequestMessage;
		}

		internal static HttpRequestMessage WithCookie( this HttpRequestMessage httpRequestMessage, string cookieValue ) {
			return httpRequestMessage.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, cookieValue );
		}

		internal static HttpRequestMessage WithCookie( this HttpRequestMessage httpRequestMessage, string cookieName, string cookieValue ) {
			string cookieHeaderValue = cookieName + "=" + cookieValue;
			return httpRequestMessage.WithCookieHeader( cookieHeaderValue );
		}

		internal static HttpRequestMessage WithCookieHeader( this HttpRequestMessage httpRequestMessage, string cookieHeaderValue ) {
			httpRequestMessage.Headers.Add( RequestValidationConstants.Headers.COOKIE, cookieHeaderValue );
			return httpRequestMessage;
		}

		#endregion

		#region HttpRequest

		internal static HttpRequest Create() {
			return new HttpRequest( null, "http://d2l.com", null );
		}

		internal static HttpRequest WithAuthHeader( this HttpRequest httpRequest, string authHeaderValue ) {
			AddHeader( httpRequest, RequestValidationConstants.Headers.AUTHORIZATION, RequestValidationConstants.BearerTokens.SCHEME_PREFIX + authHeaderValue );
			return httpRequest;
		}

		internal static HttpRequest WithAuthHeader( this HttpRequest httpRequest, string scheme, string authHeaderValue ) {
			AddHeader( httpRequest, RequestValidationConstants.Headers.AUTHORIZATION, scheme + " " + authHeaderValue );
			return httpRequest;
		}

		internal static HttpRequest WithXsrfHeader( this HttpRequest httpRequest, string xsrfHeaderValue ) {
			AddHeader( httpRequest, RequestValidationConstants.Headers.XSRF, xsrfHeaderValue );
			return httpRequest;
		}

		internal static HttpRequest WithCookie( this HttpRequest httpRequest, string cookieValue ) {
			return httpRequest.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, cookieValue );
		}

		internal static HttpRequest WithCookie( this HttpRequest httpRequest, string cookieName, string cookieValue ) {
			httpRequest.Cookies.Add( new HttpCookie( cookieName, cookieValue ) );
			return httpRequest;
		}
		
		private static void AddHeader( HttpRequest httpRequest, string headerName, string headerValue ) {

			// A hack for modifying http headers in an HttpRequest: http://stackoverflow.com/a/13307238
			NameValueCollection headers = httpRequest.Headers;
			Type headerCollectionType = headers.GetType();
			var item = new ArrayList();

			const BindingFlags flags = BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance;

			headerCollectionType.InvokeMember( "MakeReadWrite", flags, null, headers, null );
			headerCollectionType.InvokeMember( "InvalidateCachedArrays", flags, null, headers, null );
			item.Add( headerValue );
			headerCollectionType.InvokeMember( "BaseAdd", flags, null, headers, new object[] { headerName, item } );
			headerCollectionType.InvokeMember( "MakeReadOnly", flags, null, headers, null );
		}

		#endregion
	}
}
