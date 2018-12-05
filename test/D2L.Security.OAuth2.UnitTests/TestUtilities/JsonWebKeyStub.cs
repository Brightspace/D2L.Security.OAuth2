using System;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.TestUtilities {
	internal class JsonWebKeyStub : JsonWebKey {
		public static readonly TimeSpan KEY_LIFETIME = TimeSpan.FromHours( 1 );

		public JsonWebKeyStub( string id ) : base( id, DateTimeOffset.UtcNow + KEY_LIFETIME ) { }
		public JsonWebKeyStub( string id, DateTimeOffset expiresAt ) : base( id, expiresAt ) { }

		public override object ToJwkDto() {
			throw new NotImplementedException();
		}

		internal override D2LSecurityToken ToSecurityToken() {
			throw new NotImplementedException();
		}
	}
}
