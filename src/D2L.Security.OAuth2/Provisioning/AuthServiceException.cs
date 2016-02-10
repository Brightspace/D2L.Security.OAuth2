using D2L.Services.Core.Exceptions;
using System;
using System.Net;

namespace D2L.Security.OAuth2.Provisioning {
	
	/// <summary>
	/// Represents an error that occured when attempting to contact the Auth
	/// Service or an error caused by the service's response
	/// </summary>
	public sealed class AuthServiceException : ServiceException {
		
		/// <inheritdoc/>
		public override string ServiceName { get { return "Auth Service"; } }
		
		internal AuthServiceException(
			ServiceErrorType errorType,
			HttpStatusCode proposedStatusCode,
			string message = null,
			Exception innerException = null,
			HttpStatusCode serviceStatusCode = default( HttpStatusCode )
		) : base( errorType, proposedStatusCode, message, innerException, serviceStatusCode ) {}
		
		internal AuthServiceException(
			ServiceErrorType errorType,
			string message = null,
			Exception innerException = null,
			HttpStatusCode serviceStatusCode = default( HttpStatusCode )
		) : base( errorType, message, innerException, serviceStatusCode ) {}

	}
	
}
