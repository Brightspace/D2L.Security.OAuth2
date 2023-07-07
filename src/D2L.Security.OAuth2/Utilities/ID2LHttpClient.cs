using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Utilities
{
	internal interface ID2LHttpClient
	{
		/// <summary>
		/// This interface was created to allow the sync generator in D2L.CodeStyle to strip the async suffix from HttpClient calls
		/// when it tries to convert async code to sync code.
		/// </summary>
		public Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri, CancellationToken cancellationToken);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption);
		public Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri);
		public Task<HttpResponseMessage> GetAsync(string requestUri);
		public Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken);

		public Task<HttpResponseMessage> Get(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken);
		public Task<HttpResponseMessage> Get(Uri requestUri, CancellationToken cancellationToken);
		public Task<HttpResponseMessage> Get(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken);
		public Task<HttpResponseMessage> Get(Uri requestUri, HttpCompletionOption completionOption);
		public Task<HttpResponseMessage> Get(string requestUri, HttpCompletionOption completionOption);
		public Task<HttpResponseMessage> Get(Uri requestUri);
		public Task<HttpResponseMessage> Get(string requestUri);
		public Task<HttpResponseMessage> Get(string requestUri, CancellationToken cancellationToken);
	}
}
