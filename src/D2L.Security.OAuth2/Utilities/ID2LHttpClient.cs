using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Utilities
{
	public interface ID2LHttpClient : IDisposable
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

		public HttpResponseMessage Get(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken);
		public HttpResponseMessage Get(Uri requestUri, CancellationToken cancellationToken);
		public HttpResponseMessage Get(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken);
		public HttpResponseMessage Get(Uri requestUri, HttpCompletionOption completionOption);
		public HttpResponseMessage Get(string requestUri, HttpCompletionOption completionOption);
		public HttpResponseMessage Get(Uri requestUri);
		public HttpResponseMessage Get(string requestUri);
		public HttpResponseMessage Get(string requestUri, CancellationToken cancellationToken);

		public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request);

		public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken);

		public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, HttpCompletionOption completionOption);

		public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, HttpCompletionOption completionOption, CancellationToken cancellationToken);

		public HttpResponseMessage Send(HttpRequestMessage request);

		public HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken);

		public HttpResponseMessage Send(HttpRequestMessage request, HttpCompletionOption completionOption);

		public HttpResponseMessage Send(HttpRequestMessage request, HttpCompletionOption completionOption, CancellationToken cancellationToken);
	}
}
