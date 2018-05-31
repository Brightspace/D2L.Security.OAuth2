using System;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.TestUtilities {
	internal class JsonWebKeyStub : JsonWebKey {
		public static readonly TimeSpan KEY_LIFETIME = TimeSpan.FromHours( 1 );

		public JsonWebKeyStub( Guid id ) : base( id, DateTime.UtcNow + KEY_LIFETIME ) { }
		public JsonWebKeyStub( Guid id, DateTime expiresAt ) : base( id, expiresAt ) { }

		public override object ToJwkDto() {
			throw new NotImplementedException();
		}

		internal override D2LSecurityKey ToSecurityKey() {
			throw new NotImplementedException();
		}
	}
}
