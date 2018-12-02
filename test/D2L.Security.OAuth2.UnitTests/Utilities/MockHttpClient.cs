using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Utilities {

	/// <summary>
	/// A utility used to create a "mock" HttpClient that does not actually make
	/// a web request, but instead always returns a given response or throws a
	/// given exception.
	/// </summary>
	internal static class MockHttpClient {

		/// <summary>
		/// Creates a "mock" HttpClient that does not actually make a web
		/// request, but instead always returns the given response.
		/// </summary>
		/// <param name="responseStatus">
		/// The status code of the response that the HttpClient should generate
		/// </param>
		/// <param name="responseContent">
		/// The body of the response that the HttpClient should generate
		/// </param>
		/// <returns></returns>
		public static HttpClient Create(
			HttpStatusCode responseStatus,
			string responseContent = null
		) {
			var response = new HttpResponseMessage( responseStatus );
			if( responseContent != null ) {
				response.Content = new StringContent( responseContent );
			}

			return new HttpClient(
				new MockResponseHandler( () => response )
			);
		}

		/// <summary>
		/// Creates a "mock" HttpClient that does not actually make a web
		/// request, but instead always throws the given exception
		/// </summary>
		/// <param name="throwsException">
		/// The exception the HttpClient should throw
		/// </param>
		/// <returns></returns>
		public static HttpClient Create(
			Exception throwsException
		) {
			return new HttpClient(
				new MockResponseHandler( () => { throw throwsException; } )
			);
		}

		private class MockResponseHandler : DelegatingHandler {

			private readonly Func<HttpResponseMessage> m_createMockResponse;

			public MockResponseHandler(
				Func<HttpResponseMessage> mockResponseFunction
			) {
				m_createMockResponse = mockResponseFunction;
			}

			protected async override Task<HttpResponseMessage> SendAsync(
				HttpRequestMessage request,
				CancellationToken cancellationToken
			) {
				return await Task.Run( m_createMockResponse );
			}
		}

	}
}
