using System;
using System.Collections;
using System.Collections.Specialized;
using System.Reflection;
using System.Web;

namespace D2L.Security.OAuth2.Tests.Utilities {
	internal static class HttpRequestBuilder {

		internal static void AddAuthHeader( HttpRequest httpRequest, string authHeaderValue ) {

			// A hack for modifying http headers in an HttpRequest: http://stackoverflow.com/a/13307238
			NameValueCollection headers = httpRequest.Headers;
			Type headerCollectionType = headers.GetType();
			var item = new ArrayList();

			const BindingFlags flags = BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance;

			headerCollectionType.InvokeMember( "MakeReadWrite", flags, null, headers, null );
			headerCollectionType.InvokeMember( "InvalidateCachedArrays", flags, null, headers, null );
			item.Add( authHeaderValue );
			headerCollectionType.InvokeMember( "BaseAdd", flags, null, headers, new object[] { "Authorization", item } );
			headerCollectionType.InvokeMember( "MakeReadOnly", flags, null, headers, null );
		}
	}
}
