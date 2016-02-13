using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Authentication {
	public sealed class AuthenticationFailureResult : IHttpActionResult {
		private readonly Exception m_exception;

		public AuthenticationFailureResult( Exception exception ) {
			m_exception = exception;	
		}

		public Task<HttpResponseMessage> ExecuteAsync( CancellationToken cancellationToken ) {
			var response = new HttpResponseMessage( HttpStatusCode.Unauthorized );

			response.Content = new ObjectContent<Response>(
				new Response {

				},
				new JsonMediaTypeFormatter(),
				"application/problem+json"
			);

			return Task.FromResult( response );
		}

		// See https://tools.ietf.org/html/draft-nottingham-http-problem-06
		private sealed class Response {
			[JsonProperty("title")]
			public string Title { get { return "Authentication required"; } }

			[JsonProperty( "status" )]
			public long Status { get { return (long)HttpStatusCode.Unauthorized; } }

			[JsonProperty( "detail" )]
			public string Detail { get; set; }
		}

	}
}
