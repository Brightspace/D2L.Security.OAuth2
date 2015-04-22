using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Provisioning {
	internal class KidSecurityToken : NamedKeySecurityToken {

		public KidSecurityToken( string kid, SecurityKey key )
			: base( ProvisioningConstants.AssertionGrant.KEY_ID_NAME, kid, key ) { }

		public override bool CanCreateKeyIdentifierClause<T>() {
			if( typeof( T ) == typeof( NamedKeySecurityKeyIdentifierClause  ) ) {
				return true;
			}

			return base.CanCreateKeyIdentifierClause<T>();
		}

		public override T CreateKeyIdentifierClause<T>() {
			if( typeof( T ) == typeof( NamedKeySecurityKeyIdentifierClause ) ) {
				return (T)(object)new NamedKeySecurityKeyIdentifierClause(
					base.Name,
					base.Id
				);
			}

			return base.CreateKeyIdentifierClause<T>();
		}

	}
}
