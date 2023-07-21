using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Utilities {
	/// <summary>
	/// This class implements sync versions of HTTPClient methods.
	/// TODO: Replace the sync methods which are currently using Task.Run(async verison); task.Wait();
	/// With (probably) HttpWebRequest
	/// </summary>
	internal sealed class D2LHttpClient : ID2LHttpClient {
		private readonly HttpClient m_httpClient;

		public D2LHttpClient( HttpClient httpClient ) {
			m_httpClient = httpClient;
		}

		public Task<HttpResponseMessage> GetAsync( string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken )
			=> m_httpClient.GetAsync( requestUri, completionOption, cancellationToken );
		public Task<HttpResponseMessage> GetAsync( Uri requestUri, CancellationToken cancellationToken )
			=> m_httpClient.GetAsync( requestUri, cancellationToken );
		public Task<HttpResponseMessage> GetAsync( Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken )
			=> m_httpClient.GetAsync( requestUri, completionOption, cancellationToken );
		public Task<HttpResponseMessage> GetAsync( Uri requestUri, HttpCompletionOption completionOption )
			=> m_httpClient.GetAsync( requestUri, completionOption );
		public Task<HttpResponseMessage> GetAsync( string requestUri, HttpCompletionOption completionOption )
			=> m_httpClient.GetAsync( requestUri, completionOption );
		public Task<HttpResponseMessage> GetAsync( Uri requestUri )
			=> m_httpClient.GetAsync( requestUri );
		public Task<HttpResponseMessage> GetAsync( string requestUri )
			=> m_httpClient.GetAsync( requestUri );
		public Task<HttpResponseMessage> GetAsync( string requestUri, CancellationToken cancellationToken )
			=> m_httpClient.GetAsync( requestUri, cancellationToken );

		public Task<HttpResponseMessage> SendAsync( HttpRequestMessage request )
			=> m_httpClient.SendAsync( request );
		public Task<HttpResponseMessage> SendAsync( HttpRequestMessage request, CancellationToken cancellationToken )
			=> m_httpClient.SendAsync( request, cancellationToken );
		public Task<HttpResponseMessage> SendAsync( HttpRequestMessage request, HttpCompletionOption completionOption )
			=> m_httpClient.SendAsync( request, completionOption );
		public Task<HttpResponseMessage> SendAsync( HttpRequestMessage request, HttpCompletionOption completionOption, CancellationToken cancellationToken )
			=> m_httpClient.SendAsync( request, completionOption, cancellationToken );

#pragma warning disable D2L0018 // Avoid using dangerous methods
		public HttpResponseMessage Get( string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri, completionOption, cancellationToken ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( Uri requestUri, CancellationToken cancellationToken ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri, cancellationToken ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri, completionOption, cancellationToken ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( Uri requestUri, HttpCompletionOption completionOption ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri, completionOption ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( string requestUri, HttpCompletionOption completionOption ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri, completionOption ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( Uri requestUri ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( string requestUri ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Get( string requestUri, CancellationToken cancellationToken ) {
			var task = Task.Run( () => m_httpClient.GetAsync( requestUri, cancellationToken ) );
			task.Wait();
			return task.Result;
		}

		public HttpResponseMessage Send( HttpRequestMessage request ) {
			var task = Task.Run( () => m_httpClient.SendAsync( request ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Send( HttpRequestMessage request, CancellationToken cancellationToken ) {
			var task = Task.Run( () => m_httpClient.SendAsync( request, cancellationToken ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Send( HttpRequestMessage request, HttpCompletionOption completionOption ) {
			var task = Task.Run( () => m_httpClient.SendAsync( request, completionOption ) );
			task.Wait();
			return task.Result;
		}
		public HttpResponseMessage Send( HttpRequestMessage request, HttpCompletionOption completionOption, CancellationToken cancellationToken ) {
			var task = Task.Run( () => m_httpClient.SendAsync( request, completionOption, cancellationToken ) );
			task.Wait();
			return task.Result;
		}
#pragma warning restore D2L0018 // Avoid using dangerous methods

		public void Dispose() { m_httpClient.Dispose(); }
	}
}
