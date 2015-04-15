using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Validation.Request;
using Moq;

namespace D2L.Security.OAuth2.Tests.Mocks {
	public static class HttpRequestMock {

		public static Mock<HttpRequest> Create(
			string d2lApiCookieValue = null,
			string authorizationHeaderValue = null,
			string xsrfHeaderValue = null
		) {

			var mock = new Mock<HttpRequest>();

			HttpCookie d2lApiCookie = null;
			if( d2lApiCookieValue != null ) {
				d2lApiCookie = new HttpCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, d2lApiCookieValue );
			}

			var cookieCollectionMock = new Mock<HttpCookieCollection>();
			cookieCollectionMock.Setup(
				c => c.Get( RequestValidationConstants.D2L_AUTH_COOKIE_NAME )
			).Returns( d2lApiCookie );

			mock.SetupGet( r => r.Cookies ).Returns( cookieCollectionMock.Object );

			var headers = new Mock<NameValueCollection>();
			headers.Setup(
				h => h.Get( RequestValidationConstants.Headers.AUTHORIZATION )
			).Returns( authorizationHeaderValue );

			headers.Setup(
				h => h.Get( RequestValidationConstants.Headers.XSRF )
			).Returns( xsrfHeaderValue );
			
			return mock;
		}
	}
}
