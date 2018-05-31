using Microsoft.IdentityModel.Tokens;
using static D2L.CodeStyle.Annotations.Statics;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class D2LCryptoProviderFactory : CryptoProviderFactory {

		[Audited( "omsmith", "2018-05-30", "blerg" )]
		public static readonly CryptoProviderFactory Instance = new D2LCryptoProviderFactory();

		public override bool IsSupportedAlgorithm( string algorithm, SecurityKey key ) {
			key = ( key is D2LSecurityKey d2lKey )
				? d2lKey.GetKey()
				: key;

			return base.IsSupportedAlgorithm( algorithm, key );
		}

		public override SignatureProvider CreateForSigning( SecurityKey key, string algorithm ) {
			key = ( key is D2LSecurityKey d2lKey )
				? d2lKey.GetKey()
				: key;

			return base.CreateForSigning( key, algorithm );
		}

		public override SignatureProvider CreateForVerifying( SecurityKey key, string algorithm ) {
			key = ( key is D2LSecurityKey d2lKey )
				? d2lKey.GetKey()
				: key;

			return base.CreateForVerifying( key, algorithm );
		}
	}
}
