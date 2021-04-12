using System;
using D2L.CodeStyle.Annotations;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class NullCryptoProviderCache : CryptoProviderCache {

		[Statics.Audited(
			owner: "Owen Smith",
			auditedDate: "2021-04-12",
			rationale: "No state"
		)]
		internal static readonly NullCryptoProviderCache Instance = new NullCryptoProviderCache();

		private NullCryptoProviderCache() { }

		public override bool TryAdd( SignatureProvider signatureProvider )
			=> throw new InvalidOperationException();
		public override bool TryGetSignatureProvider( SecurityKey securityKey, string algorithm, string typeofProvider, bool willCreateSignatures, out SignatureProvider signatureProvider )
			=> throw new InvalidOperationException();
		public override bool TryRemove( SignatureProvider signatureProvider )
			=> throw new InvalidOperationException();
		protected override string GetCacheKey( SignatureProvider signatureProvider )
			=> throw new InvalidOperationException();
		protected override string GetCacheKey( SecurityKey securityKey, string algorithm, string typeofProvider )
			=> throw new InvalidOperationException();
	}
}
