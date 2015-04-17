using System;
using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys {
	internal sealed class D2LSigningCredentials : SigningCredentials, IDisposable {
		public D2LSigningCredentials(
			Guid id,
			SecurityKey signingKey,
			string signatureAlgorithm,
			string digestAlgorithm
		) : base(
			signingKey,
			signatureAlgorithm,
			digestAlgorithm,
			new SecurityKeyIdentifier( new NamedKeySecurityKeyIdentifierClause( JsonWebKey.KEY_ID, id.ToString() ) )
		) {}

		public D2LSigningCredentials(
			SecurityKey signingKey,
			string signatureAlgorithm,
			string digestAlgorithm,
			SecurityKeyIdentifier signingKeyIdentifier
		) : base(
			signingKey,
			signatureAlgorithm,
			digestAlgorithm,
			signingKeyIdentifier
		) {}

		public void Dispose() {
			var key = SigningKey as AsymmetricSecurityKey;
			var csp = key.GetAsymmetricAlgorithm( "", key.HasPrivateKey() );
			csp.Dispose();
		}
	}
}
