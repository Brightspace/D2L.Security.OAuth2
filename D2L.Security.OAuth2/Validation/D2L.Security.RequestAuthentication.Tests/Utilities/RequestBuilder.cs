using System;
using System.Collections;
using System.Collections.Specialized;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Web;

namespace D2L.Security.RequestAuthentication.Tests.Utilities {
	internal static class RequestBuilder {

		private const string D2L_AUTH_COOKIE_NAME = "d2lApi";
		private const string COOKIE_HEADER_NAME = "Cookie";
		private const string AUTH_HEADER_SCHEME = "Bearer";
		private const string BEARER_TOKEN_HEADER_NAME = "Authorization";
		private const string XSRF_HEADER_NAME = "X-Csrf-Token";

		internal static void AddAuthHeader( HttpRequest httpRequest, string authHeaderValue ) {
			AddHeader( httpRequest, BEARER_TOKEN_HEADER_NAME, authHeaderValue );
		}

		internal static void AddXsrfHeader( HttpRequest httpRequest, string xsrfHeaderValue ) {
			AddHeader( httpRequest, XSRF_HEADER_NAME, xsrfHeaderValue );
		}

		internal static void AddCookie( HttpRequest httpRequest, string cookieValue ) {
			httpRequest.Cookies.Add( new HttpCookie( D2L_AUTH_COOKIE_NAME, cookieValue ) );
		}

		internal static void AddAuthHeader( HttpRequestMessage httpRequestMessage, string authHeaderValue ) {
			AuthenticationHeaderValue authHeaderVal = new AuthenticationHeaderValue( AUTH_HEADER_SCHEME, authHeaderValue );
			httpRequestMessage.Headers.Authorization = authHeaderVal;
		}

		internal static void AddXsrfHeader( HttpRequestMessage httpRequestMessage, string xsrfHeaderValue ) {
			httpRequestMessage.Headers.Add( XSRF_HEADER_NAME, xsrfHeaderValue );
		}

		internal static void AddCookie( HttpRequestMessage httpRequestMessage, string cookieValue ) {
			string cookieHeaderValue = D2L_AUTH_COOKIE_NAME + "=" + cookieValue;
			httpRequestMessage.Headers.Add( COOKIE_HEADER_NAME, cookieHeaderValue );
		}

		private static void AddHeader( HttpRequest httpRequest, string headerName, string headerValue ) {

			// A hack for modifying http headers in an HttpRequest: http://stackoverflow.com/a/13307238
			NameValueCollection headers = httpRequest.Headers;
			Type headerCollectionType = headers.GetType();
			ArrayList item = new ArrayList();

			const BindingFlags flags = BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance;

			headerCollectionType.InvokeMember( "MakeReadWrite", flags, null, headers, null );
			headerCollectionType.InvokeMember( "InvalidateCachedArrays", flags, null, headers, null );
			item.Add( headerValue );
			headerCollectionType.InvokeMember( "BaseAdd", flags, null, headers, new object[] { headerName, item } );
			headerCollectionType.InvokeMember( "MakeReadOnly", flags, null, headers, null );
		}
	}
}
