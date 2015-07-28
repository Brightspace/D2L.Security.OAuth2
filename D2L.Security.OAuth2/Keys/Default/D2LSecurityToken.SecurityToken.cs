using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using D2L.Security.OAuth2.Provisioning;

namespace D2L.Security.OAuth2.Keys.Default {

	partial class D2LSecurityToken : SecurityToken {

		public override string Id { get { return KeyId.ToString(); } }

		public override ReadOnlyCollection<SecurityKey> SecurityKeys {
			get {
				return new ReadOnlyCollection<SecurityKey>(
					new List<SecurityKey> { GetKey() }
				);
			}
		}

		public override SecurityKey ResolveKeyIdentifierClause(
			SecurityKeyIdentifierClause keyIdentifierClause
		) {
			if( MatchesKeyIdentifierClause( keyIdentifierClause ) ) {
				return GetKey();
			}

			return null;
		}

		public override bool MatchesKeyIdentifierClause( SecurityKeyIdentifierClause keyIdentifierClause ) {
			if( keyIdentifierClause == null ) {
				throw new ArgumentNullException( "keyIdentifierClause" );
			}

			var clause = keyIdentifierClause as NamedKeySecurityKeyIdentifierClause;
			return clause != null
				&& clause.Name.Equals( ProvisioningConstants.AssertionGrant.KEY_ID_NAME, StringComparison.Ordinal )
				&& clause.Id.Equals( this.KeyId.ToString(), StringComparison.OrdinalIgnoreCase );
		}
	}
}
