using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;
using D2L.Services.Core.Exceptions;

#if NET6_0
using JsonPropertyNameAttribute = System.Text.Json.Serialization.JsonPropertyNameAttribute;
#else
using JsonPropertyNameAttribute = Newtonsoft.Json.JsonPropertyAttribute;
#endif

namespace D2L.Security.OAuth2.Provisioning.Default {

	/// <summary>
	/// Calls the Auth Service to provision access tokens
	/// </summary>
	[SuppressMessage(
		"Correctness",
		"D2L0096:Aliasing attribute class names not supported",
		Justification = "Newtonsoft.Json.JsonPropertyAttribute is aliased to match System.Text.Json.Serialization.JsonPropertyNameAttribute to reduce duplication below."
	)]
	internal sealed class AuthServiceClient : IAuthServiceClient {

		private const string TOKEN_PATH = "/connect/token";

		private const string SERIALIZATION_ERROR_MESSAGE_PREFIX =
			"An error occurred while parsing the response from the Auth Service. ";

		internal const string EMPTY_RESPONSE_ERROR_MESSAGE =
			SERIALIZATION_ERROR_MESSAGE_PREFIX +
			"The Auth Service's reponse did not have any content.";

		internal const string INVALID_JSON_ERROR_MESSAGE_PREFIX =
			SERIALIZATION_ERROR_MESSAGE_PREFIX +
			"The Auth Service responded with: ";

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
					response = await MakeRequest( requestBody ).ConfigureAwait( false );
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

				string json = null;
				if( response.Content != null ) {
					try {
						json = await response.Content.ReadAsStringAsync().ConfigureAwait( false );
					} catch( Exception exception ) {
						throw new AuthServiceException(
							errorType: ServiceErrorType.ClientError,
							message: "An unkown error occurred reading the response body.",
							innerException: exception
						);
					}
				}


				if( !response.IsSuccessStatusCode ) {
					string errorMessage;

					if( string.IsNullOrWhiteSpace( json ) ) {
						errorMessage = response.ReasonPhrase;
					} else {
						try {
							var errorInfo = JsonSerializer.Deserialize<ErrorResponse>( json );
							errorInfo.Validate();
							errorMessage = string.Concat( errorInfo.Title, ": ", errorInfo.Detail );
						} catch( Exception ) {
							errorMessage = string.Concat( response.ReasonPhrase, ": ", json );
						}
					}

					throw new AuthServiceException(
						errorType: ServiceErrorType.ErrorResponse,
						serviceStatusCode: response.StatusCode,
						message: errorMessage
					);
				}

				if( string.IsNullOrEmpty( json ) ) {
					throw new AuthServiceException(
						errorType: ServiceErrorType.ClientError,
						message: EMPTY_RESPONSE_ERROR_MESSAGE
					);
				}

				try {
					var grant = JsonSerializer.Deserialize<GrantResponse>( json );
					grant.Validate();
					return new AccessToken( grant.Token );
				} catch( Exception exception ) {
					throw new AuthServiceException(
						errorType: ServiceErrorType.ClientError,
						message: string.Concat( INVALID_JSON_ERROR_MESSAGE_PREFIX, json ),
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

		private sealed class GrantResponse {
			[JsonPropertyName( "access_token" )]
			public string Token { get; set; }

			internal void Validate() {
				if ( Token == null ) {
					throw new Exception( "Missing property: access_token" );
				}
			}
		}

		private sealed class ErrorResponse {
			[JsonPropertyName( "error" )]
			public string Title { get; set; }

			[JsonPropertyName( "error_description" )]
			public string Detail { get; set; }

			internal void Validate() {
				if ( Title == null ) {
					throw new Exception( "Missing property: error" );
				}

				if ( Detail == null ) {
					throw new Exception( "Missing property: error_description" );
				}
			}
		}
	}
}
