using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Utilities
{
	internal class D2LHttpClient
	{
		/// <summary>
		/// This class implements sync versions of HTTPClient methods.
		/// TODO: Replace the sync methods which are currently using Task.Run(async verison); task.Wait();
		/// With (probably) HttpWebRequest
		/// </summary>
		private readonly HttpClient m_httpClient = new HttpClient();

		public Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken)
			=> m_httpClient.GetAsync(requestUri, completionOption, cancellationToken);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri, CancellationToken cancellationToken)
			=> m_httpClient.GetAsync(requestUri, cancellationToken);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken)
			=> m_httpClient.GetAsync(requestUri, completionOption, cancellationToken);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption)
			=> m_httpClient.GetAsync(requestUri, completionOption);
		public Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption)
			=> m_httpClient.GetAsync(requestUri, completionOption);
		public Task<HttpResponseMessage> GetAsync(Uri requestUri)
			=> m_httpClient.GetAsync(requestUri);
		public Task<HttpResponseMessage> GetAsync(string requestUri)
			=> m_httpClient.GetAsync(requestUri);
		public Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken)
			=> m_httpClient.GetAsync(requestUri, cancellationToken);

#pragma warning disable D2L0018 // Avoid using dangerous methods
		public HttpResponseMessage Get(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri, completionOption, cancellationToken));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(Uri requestUri, CancellationToken cancellationToken) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri, cancellationToken));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri, completionOption, cancellationToken));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(Uri requestUri, HttpCompletionOption completionOption) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri, completionOption));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(string requestUri, HttpCompletionOption completionOption) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri, completionOption));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(Uri requestUri) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(string requestUri) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri));
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get(string requestUri, CancellationToken cancellationToken) {
			var task = Task.Run(() => m_httpClient.GetAsync(requestUri, cancellationToken));
			task.Wait();
			return task.Result;
		}
#pragma warning restore D2L0018 // Avoid using dangerous methods
	}
}
