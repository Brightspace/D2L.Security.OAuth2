using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using D2L.Services.Core.Exceptions;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {

	/// <summary>
	/// Calls the Auth Service to provision access tokens
	/// </summary>
	internal sealed class AuthServiceClient : IAuthServiceClient {

		private const string TOKEN_PATH = "/connect/token";

		private readonly HttpClient m_client;
		private readonly Uri m_tokenProvisioningEndpoint;

		/// <summary>
		/// Constructs a new <see cref="AuthServiceClient"/>
		/// </summary>
		/// <param name="httpClient">An http client used to communicate with the auth service.</param>
		/// <param name="authEndpoint">The token provisioning endpoint on the auth service</param>
		public AuthServiceClient(
			HttpClient httpClient,
			Uri authEndpoint
		) {
			if( httpClient == null ) {
				throw new ArgumentNullException( "httpClient" );
			}

			if( authEndpoint == null ) {
				throw new ArgumentNullException( "authEndpoint" );
			}

			m_client = httpClient;
			m_tokenProvisioningEndpoint = new Uri( authEndpoint + TOKEN_PATH );
		}

		/// <summary>
		/// Provisions an access token from the auth service
		/// </summary>
		/// <param name="assertion">A JWT signed by the private key of the entity requesting the token</param>
		/// <param name="scopes">List of scopes to include in the access token</param>
		/// <returns>A JWT token from the auth service signed with the auth service's private key</returns>
		/// <exception cref="AuthServiceException">
		/// The auth service could not be reached, or it did not respond with
		/// a status code indicating success.
		/// </exception>
		async Task<IAccessToken> IAuthServiceClient.ProvisionAccessTokenAsync(
			string assertion,
			IEnumerable<Scope> scopes
		) {
			string requestBody = BuildFormContents( assertion, scopes );
			HttpResponseMessage response = null;
			try {
				try {
					response = await MakeRequest( requestBody ).SafeAsync();
				} catch( TaskCanceledException exception ) {
					throw new AuthServiceException(
						errorType: ServiceErrorType.Timeout,
						message: "The web request to the Auth Service has timed out.",
						innerException: exception
					);
				} catch( Exception exception ) {
					throw new AuthServiceException(
						errorType: ServiceErrorType.ConnectionFailure,
						message: "Could not establish a connection with the Auth Service.",
						innerException: exception
					);
				}
				
				if( !response.IsSuccessStatusCode ) {
					throw new AuthServiceException(
						errorType: ServiceErrorType.ErrorResponse,
						serviceStatusCode: response.StatusCode,
						message: string.Concat(
							"The Auth Service did not respond with a status code indicating success. ",
							"(Received ", ((int)response.StatusCode).ToString(), " ",
							response.ReasonPhrase, ")"
						)
					);
				}
				
				try {
					using( var resultStream = await response.Content.ReadAsStreamAsync().SafeAsync() ) {
						IAccessToken accessToken = SerializationHelper.ExtractAccessToken( resultStream );
						return accessToken;
					}
				} catch( Exception exception ) {
					throw new AuthServiceException(
						errorType: ServiceErrorType.ClientError,
						message: "An error occurred in parsing the response from the Auth Service.",
						innerException: exception
					);
				}
			} finally {
				if( response != null ) {
					response.Dispose();
				}
			}
		}

		private Task<HttpResponseMessage> MakeRequest( string body ) {
			var request = new HttpRequestMessage( HttpMethod.Post, m_tokenProvisioningEndpoint );
			request.Content = new StringContent( body, Encoding.UTF8, "application/x-www-form-urlencoded" );

			return m_client.SendAsync( request );
		}

		private static string BuildFormContents( string assertion, IEnumerable<Scope> scopes ) {
			StringBuilder builder = new StringBuilder( "grant_type=" );
			builder.Append( WebUtility.UrlEncode( Constants.GrantTypes.JWT_BEARER ) );

			builder.Append( "&assertion=" );
			builder.Append( assertion );

			var scopesString = String.Join( " ", scopes );
			scopesString = WebUtility.UrlEncode( scopesString );
			builder.Append( "&scope=" );
			builder.Append( scopesString );

			var result = builder.ToString();
			return result;
		}
	}
}
